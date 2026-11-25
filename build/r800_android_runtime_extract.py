#!/usr/bin/env python3
"""Extract selected files from a trusted Android 11 ARM64 runtime APEX.

Input: standalone APEX ZIP, or raw/sparse ext4 system.img with a runtime APEX.
Read-only debugfs, no host mount, no root privileges, no donor execution.
The caller supplies the expected donor digest; this is not signature validation.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import zipfile

from r800_android_dynamic_audit import inspect_elf, RUNTIME, LIBS, MAX_ELF

MAX_SYSTEM = 8 * 1024**3
MAX_APEX = 256 * 1024**2
MAX_PAYLOAD = 256 * 1024**2
SPARSE_MAGIC = b"\x3a\xff\x26\xed"
APEX_PATHS = ("/apex/com.android.runtime.apex",
              "/system/apex/com.android.runtime.apex")
FILES = ("bin/linker64",) + tuple("lib64/bionic/" + lib for lib in LIBS)


def digest(path: Path, limit: int) -> str:
    if path.is_symlink() or not path.is_file():
        raise ValueError("Input must be a regular non-symlink file")
    if not 0 < path.stat().st_size <= limit:
        raise ValueError("Input size outside limit")
    h = hashlib.sha256()
    total = 0
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            total += len(chunk)
            if total > limit:
                raise ValueError("Input grew beyond limit")
            h.update(chunk)
    return h.hexdigest()


def ext4(path: Path) -> None:
    with path.open("rb") as stream:
        stream.seek(1080)
        if stream.read(2) != b"\x53\xef":
            raise ValueError("Expected ext4 filesystem image")


def dump_file(image: Path, source: str, destination: Path, limit: int) -> None:
    # All source paths are fixed by this program, not donor directory names.
    # debugfs command parser accepts quoted output paths, but reject special
    # characters rather than passing ambiguous commands.
    if not re.fullmatch(r"/[A-Za-z0-9_./-]+", source):
        raise ValueError("Invalid fixed source path")
    if not re.fullmatch(r"[A-Za-z0-9_./-]+", str(destination)):
        raise ValueError("Unsupported scratch path")
    if destination.exists():
        raise ValueError("Destination already exists")
    command = ["debugfs", "-R", "stat " + source, str(image)]
    result = subprocess.run(command, capture_output=True, text=True, timeout=30, check=True,
                            env={**os.environ, "LC_ALL": "C"})
    match = re.search(r"^Inode:\s+\d+\s+Type:\s+regular\b", result.stdout, re.M)
    sizes = re.findall(r"^User:[^\n]*?\bSize:\s*(\d+)", result.stdout, re.M)
    if not match or len(sizes) != 1 or not 0 < int(sizes[0]) <= limit:
        raise ValueError("Missing or invalid regular file in image: " + source)
    subprocess.run(["debugfs", "-R", f"dump {source} {destination}", str(image)],
                   capture_output=True, timeout=60, check=True)
    if destination.is_symlink() or not destination.is_file() or destination.stat().st_size != int(sizes[0]):
        raise ValueError("Incomplete debugfs extraction: " + source)


def extract_payload(apex: Path, target: Path) -> None:
    digest(apex, MAX_APEX)
    with zipfile.ZipFile(apex) as z:
        entries = [i for i in z.infolist() if i.filename == "apex_payload.img"]
        if len(entries) != 1:
            raise ValueError("Expected exactly one APEX payload entry (CAPEX unsupported)")
        entry = entries[0]
        if entry.is_dir() or not 0 < entry.file_size <= MAX_PAYLOAD:
            raise ValueError("Invalid APEX payload size")
        # Do not extract other archive entries or use donor paths on host.
        with z.open(entry) as src, target.open("xb") as dst:
            remaining = entry.file_size
            while remaining:
                chunk = src.read(min(1024 * 1024, remaining))
                if not chunk:
                    raise ValueError("Truncated APEX payload")
                dst.write(chunk)
                remaining -= len(chunk)
            if src.read(1):
                raise ValueError("Oversized APEX payload")
    ext4(target)


def unpack_system(donor: Path, scratch: Path) -> Path:
    with donor.open("rb") as f:
        header = f.read(28)
    if header[:4] == SPARSE_MAGIC:
        if len(header) != 28:
            raise ValueError("Truncated Android sparse header")
        if int.from_bytes(header[4:6], "little") != 1 or int.from_bytes(header[8:10], "little") < 28 or int.from_bytes(header[10:12], "little") < 12:
            raise ValueError("Unsupported Android sparse header")
        block_size = int.from_bytes(header[12:16], "little")
        blocks = int.from_bytes(header[16:20], "little")
        if block_size != 4096 or not 0 < block_size * blocks <= MAX_SYSTEM:
            raise ValueError("Sparse expansion outside size limit")
        raw = scratch / "system.raw"
        subprocess.run(["simg2img", str(donor), str(raw)], check=True, timeout=300,
                       capture_output=True)
        if raw.stat().st_size != block_size * blocks:
            raise ValueError("Sparse expansion size mismatch")
    else:
        raw = donor
    ext4(raw)
    return raw


def extract(donor: Path, expected: str, out: Path, readelf: str = "readelf") -> dict:
    if not re.fullmatch(r"[0-9a-f]{64}", expected):
        raise ValueError("Expected lowercase SHA-256 donor digest")
    if digest(donor, MAX_SYSTEM) != expected:
        raise ValueError("Donor SHA-256 mismatch")
    if out.exists() or out.is_symlink():
        raise ValueError("Output must be new")
    with tempfile.TemporaryDirectory(prefix="galwear-runtime-") as temp:
        scratch = Path(temp)
        if zipfile.is_zipfile(donor):
            apex = donor
            origin = "standalone-apex"
        else:
            raw = unpack_system(donor, scratch)
            found = []
            for i, source in enumerate(APEX_PATHS):
                candidate = scratch / f"runtime{i}.apex"
                try:
                    dump_file(raw, source, candidate, MAX_APEX)
                except ValueError:
                    continue
                found.append((source, candidate))
            if len(found) != 1:
                raise ValueError("Expected one runtime APEX in known system paths")
            origin, apex = found[0]
        apex_sha = digest(apex, MAX_APEX)
        payload = scratch / "apex_payload.img"
        extract_payload(apex, payload)
        payload_sha = digest(payload, MAX_PAYLOAD)
        stage = scratch / "root"
        runtime = stage / RUNTIME
        inventory = {}
        for name in FILES:
            dest = runtime / name
            dest.parent.mkdir(parents=True, exist_ok=True)
            dump_file(payload, "/" + name, dest, MAX_ELF)
            info = inspect_elf(dest, readelf)
            if info["elf_type"] != 3 or info["interpreter"] is not None:
                raise ValueError("Unexpected runtime ELF: " + name)
            if name.startswith("lib64/") and info["soname"] != dest.name:
                raise ValueError("Unexpected runtime SONAME: " + name)
            if name == "bin/linker64" and info["needed"]:
                raise ValueError("Unexpected linker dependencies")
            if not set(info["needed"]) <= set(LIBS):
                raise ValueError("Dependency outside minimal runtime: " + name)
            dest.chmod(0o755 if name == "bin/linker64" else 0o644)
            inventory[name] = info
        if digest(donor, MAX_SYSTEM) != expected:
            raise ValueError("Donor changed during extraction")
        # Materialize only audited files in a new directory. The alias uses a
        # relative target so it resolves inside the staged tree, not on host.
        out.mkdir()
        shutil.copytree(runtime, out / RUNTIME)
        (out / "system/bin").mkdir(parents=True)
        (out / "system/bin/linker64").symlink_to("../../apex/com.android.runtime/bin/linker64")
        return {"status": "ANDROID_RUNTIME_EXTRACTED_STATIC_ONLY",
                "donor_sha256": expected, "apex_origin": origin,
                "apex_sha256": apex_sha, "payload_sha256": payload_sha,
                "files": inventory, "runtime_authenticity_verified": False,
                "runtime_stub_exclusion_proven": False,
                "linkerconfig_generated": False, "dynamic_android_linker_tested": False,
                "safe_to_flash": False}


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--donor", type=Path, required=True)
    p.add_argument("--sha256", required=True)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--report", type=Path, required=True)
    p.add_argument("--readelf", default="readelf")
    p.add_argument("--resolved-manifest", type=Path)
    a = p.parse_args()
    try:
        report = extract(a.donor, a.sha256, a.out, a.readelf)
        if a.resolved_manifest is not None:
            from r800_aosp_artifact_origin import manifest_digest
            report["resolved_manifest_sha256"] = manifest_digest(a.resolved_manifest)
        rc = 0
    except (OSError, ValueError, zipfile.BadZipFile, subprocess.SubprocessError) as exc:
        report = {"status": "REJECT", "reason": str(exc), "safe_to_flash": False}
        rc = 2
    a.report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(report["status"])
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
