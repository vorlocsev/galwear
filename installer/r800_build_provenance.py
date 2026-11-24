#!/usr/bin/env python3
"""Read-only release input audit and SHA-256 build evidence for SM-R800.

Preflight rejects unsafe/unknown Samsung combination entries and accidental
watch-specific state inside payload.tar BEFORE the root-only build mounts or
extracts any image. Finalize compares hashes against the initial snapshot.

This is evidence of *which local bytes were used*, not authenticity,
bit-for-bit reproducibility or bootloader/device compatibility.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import posixpath
import struct
import sys
import tarfile

from r800_safety import SafetyError, preflight_file
from r800_recovery_audit import COPIED_FROM_COMBINATION, audit_release


SCHEMA = "galwear-r800-build-evidence-v1"
REQUIRED_COMBINATION = frozenset((*COPIED_FROM_COMBINATION, "user.img", "csc.img"))
# mkpayload-release.sh must strip flags from the *device's* /android tree.
NEVER_SHIP_ANDROID_FILES = frozenset((
    "DEV", "STAY", "SLEEP", "CPUIDLE_DEEP", "OVERLAY",
    "gemini.tries", "userdata.img", "RESET_DATA",
))
SOURCE_FILES = (
    "build/mkrelease.sh",
    "build/mkpayload-release.sh",
    "build/mkboot.sh",
    "payload/start.sh",
    "payload/android-helper.sh",
    "payload/dockrot.sh",
    "payload/udhcpc.sh",
    "payload/repair.sh",
    "src/tools/sensors/tzchroot.sh",
    "src/dt/r800.dts",
    "src/kernel/r800.config",
    "src/kernel/r800-wearos.patch",
)
IMAGE_FILES = (
    "images/samsung/COMBINATION-FT40_R800XXU1ARI2_noCM.tar.md5",
    "images/boot/r800-boot.img",
    "images/vendor.img",
    "images/payload.tar",
)
RELEASE_IMAGE = "images/R800-WearOS.tar.md5"
MAX_COMBO_MEMBERS = 128
MAX_PAYLOAD_MEMBERS = 30000
MAX_BOOT_BYTES = 64 * 1024 * 1024
MAX_DTB_BYTES = 4 * 1024 * 1024


def digest(path: Path) -> dict[str, str | int]:
    if not path.is_file() or path.is_symlink():
        raise SafetyError(f"Missing or symlinked input: {path.name}")
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for data in iter(lambda: stream.read(4 * 1024 * 1024), b""):
            h.update(data)
    return {"size_bytes": path.stat().st_size, "sha256": h.hexdigest()}


def safe_tar_name(name: str) -> bool:
    """Names must be canonical, relative, and never cross the TAR root."""
    if not name or name in (".", "./"):
        return False
    if name.startswith("/") or "\\" in name or "//" in name:
        return False
    parts = name.rstrip("/").split("/")
    if any(p in ("", ".", "..") for p in parts):
        return False
    return posixpath.normpath(name).rstrip("/") == name.rstrip("/")


def validate_combination(path: Path) -> dict[str, int]:
    """Inspect members but never extract binary firmware."""
    with tarfile.open(path, "r:") as archive:
        members = archive.getmembers()
        if not 1 <= len(members) <= MAX_COMBO_MEMBERS:
            raise SafetyError("Unexpected combination archive member count")
        files: set[str] = set()
        for member in members:
            if not safe_tar_name(member.name):
                raise SafetyError(f"Unsafe combination TAR member: {member.name!r}")
            if not member.isfile():
                raise SafetyError(f"Non-regular combination TAR member: {member.name!r}")
            if member.name in files:
                raise SafetyError(f"Duplicate combination member: {member.name}")
            if member.name in ("cm.bin", "csa.img", "efs.img"):
                raise SafetyError(f"Forbidden combination member: {member.name}")
            files.add(member.name)
        missing = REQUIRED_COMBINATION - files
        if missing:
            raise SafetyError("Combination lacks " + ", ".join(sorted(missing)))
    return {"regular_files": len(files), "required_files": len(REQUIRED_COMBINATION)}


def validate_payload(path: Path) -> dict[str, int]:
    """Never ship experimental power flags, device state or unsafe TAR paths."""
    found: set[str] = set()
    with tarfile.open(path, "r:") as archive:
        members = archive.getmembers()
        if not 1 <= len(members) <= MAX_PAYLOAD_MEMBERS:
            raise SafetyError("Unexpected payload member count")
        for member in members:
            name = member.name
            if not safe_tar_name(name):
                raise SafetyError(f"Unsafe payload TAR path: {name!r}")
            if name in found:
                raise SafetyError(f"Duplicate payload member: {name}")
            found.add(name)
            if not name.startswith("r800dev/"):
                raise SafetyError(f"Unexpected payload root: {name}")
            relative = name[len("r800dev/"):]
            if relative.startswith("android/") and relative.split("/", 1)[1] in NEVER_SHIP_ANDROID_FILES:
                raise SafetyError(f"Watch-specific/experimental payload file: {name}")
            if not (member.isfile() or member.isdir() or member.issym()):
                raise SafetyError(f"Unsafe payload entry type: {name}")
            if member.issym():
                target = member.linkname
                if (not target or target.startswith("/") or "\\" in target or
                        ".." in target.split("/")):
                    raise SafetyError(f"Unsafe payload symlink: {name} -> {target}")
                resolved = posixpath.normpath(
                    posixpath.join(posixpath.dirname(name), target))
                if not resolved.startswith("r800dev/"):
                    raise SafetyError(f"Payload symlink escapes root: {name}")
            if name == "r800dev/android/persistent.img":
                if not member.isfile() or member.size != 1024 * 1024:
                    raise SafetyError("Persistent FRP image must be 1 MiB of zeros")
                stream = archive.extractfile(member)
                if stream is None or any(byte != 0 for chunk in iter(
                        lambda: stream.read(1024 * 1024), b"") for byte in chunk):
                    raise SafetyError("Persistent FRP image contains nonzero data")
        required = {
            "r800dev/start.sh",
            "r800dev/android-helper.sh",
            "r800dev/android/persistent.img",
        }
        missing = required - found
        if missing:
            raise SafetyError("Payload lacks " + ", ".join(sorted(missing)))
    return {"total_members": len(found), "required_files": len(required)}


def validate_boot(path: Path) -> dict[str, int]:
    """Check NZIT and EXYN boundaries, not signature validity."""
    size = path.stat().st_size
    if not 2048 + 272 <= size <= MAX_BOOT_BYTES:
        raise SafetyError(f"Boot image size outside supported range: {size}")
    with path.open("rb") as stream:
        hdr = stream.read(2048)
        magic, alignment, kernel_size, _total, dt_size, _ramdisk, header_size = (
            struct.unpack_from("<7I", hdr))
        if (magic != 0x54495A4E or header_size != 2048 or
                not kernel_size or not 12 <= dt_size <= MAX_DTB_BYTES or
                alignment == 0 or alignment & (alignment - 1)):
            raise SafetyError("Invalid boot NZIT header")
        dt_offset = 2048 + ((kernel_size + 2047) & ~2047)
        if dt_offset + dt_size + 272 > size:
            raise SafetyError("Boot NZIT kernel/DTB/signature bounds invalid")
        stream.seek(dt_offset)
        table = stream.read(dt_size)
        if len(table) != dt_size:
            raise SafetyError("Truncated boot EXYN data")
        marker, _ver, count = struct.unpack_from("<3I", table)
        if marker != 0x4E595845 or not 1 <= count <= 64 or 12 + 20 * count > dt_size:
            raise SafetyError("Invalid boot EXYN table")
        for index in range(count):
            _, _, _, offset, length = struct.unpack_from(
                "<5I", table, 12 + index * 20)
            if not length or offset < 12 + count * 20 or offset + length > dt_size:
                raise SafetyError("Boot EXYN DTB out of bounds")
    return {"size_bytes": size, "kernel_bytes": kernel_size,
            "dt_bytes": dt_size, "dtb_entries": count}


def prebuild(release: Path) -> dict:
    """Inspect required sources and binary inputs; no privileged operations."""
    if not release.is_dir():
        raise SafetyError("Release source tree does not exist")
    sources = {name: digest(release / name) for name in SOURCE_FILES}
    inputs = {name: digest(release / name) for name in IMAGE_FILES}
    checks = {
        "combination": validate_combination(release / IMAGE_FILES[0]),
        "boot": validate_boot(release / IMAGE_FILES[1]),
        "payload": validate_payload(release / IMAGE_FILES[3]),
    }
    # vendor.img is ext4; its superblock magic resides at offset 1080.
    vendor = release / IMAGE_FILES[2]
    with vendor.open("rb") as stream:
        stream.seek(1080)
        if stream.read(2) != b"\x53\xef":
            raise SafetyError("vendor.img lacks ext4 magic at 1080")
    checks["vendor"] = {"ext4_magic": True}
    return {
        "schema": SCHEMA,
        "status": "PREBUILD_INPUTS_CHECKED",
        "sources": sources,
        "inputs": inputs,
        "checks": checks,
        "source_authenticity_verified": False,
        "bit_for_bit_reproducibility_verified": False,
        "device_compatibility_verified": False,
        "safe_to_flash": False,
    }


def finalize(release: Path, previous: dict) -> dict:
    """Require identical inputs since preflight; compare final recovery images."""
    if previous.get("schema") != SCHEMA or previous.get("status") != "PREBUILD_INPUTS_CHECKED":
        raise SafetyError("Missing/invalid initial build evidence")
    current = prebuild(release)
    if previous["sources"] != current["sources"] or previous["inputs"] != current["inputs"]:
        raise SafetyError("Build input/source changed since preflight")
    package = release / RELEASE_IMAGE
    members = preflight_file(package)
    comparison = audit_release(package, release / IMAGE_FILES[0])
    result = dict(current)
    result["status"] = "RELEASE_OUTPUT_STRUCTURAL_PASS_ONLY"
    result["release"] = {
        **digest(package),
        "name": package.name,
        "member_count": len(members),
        "matching_combination_components": len(comparison["checks"]),
        "nzit": comparison["nzit"],
    }
    # This never proves the reference is genuine Samsung software.
    return result


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Read-only SM-R800 build evidence (no flash)")
    parser.add_argument("action", choices=("preflight", "finalize"))
    parser.add_argument("--release-tree", type=Path, required=True)
    parser.add_argument("--input-manifest", type=Path,
                        help="Preflight JSON for finalize")
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.action == "preflight":
            result = prebuild(args.release_tree)
        else:
            if args.input_manifest is None:
                raise SafetyError("Finalize requires --input-manifest")
            result = finalize(args.release_tree,
                              json.loads(args.input_manifest.read_text(encoding="utf-8")))
        args.report.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n",
                               encoding="utf-8")
        print(f"[PASS] {result['status']}; NOT authenticity or flash safety proof.")
        return 0
    except (SafetyError, OSError, ValueError, KeyError, tarfile.TarError) as exc:
        print(f"[REJECT] {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
