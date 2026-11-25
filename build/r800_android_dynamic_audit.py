#!/usr/bin/env python3
"""Inspect a dynamic AArch64 Android executable and an explicitly supplied runtime.

No mounting, extraction, execution or firmware packaging. An inventory alone
does not establish Android compatibility or donor authenticity.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

INTERP = "/system/bin/linker64"
RUNTIME = "apex/com.android.runtime"
LIBS = ("libc.so", "libdl.so", "libm.so")
MAX_ELF = 32 * 1024 * 1024


def inspect_elf(path: Path, readelf: str = "readelf") -> dict:
    if path.is_symlink() or not path.is_file() or not 64 <= path.stat().st_size <= MAX_ELF:
        raise ValueError("Missing, symlinked or oversized ELF: " + str(path))
    data = path.read_bytes()
    if data[:6] != b"\x7fELF\x02\x01" or int.from_bytes(data[18:20], "little") != 183:
        raise ValueError("Expected little-endian AArch64 ELF")
    info = subprocess.run([readelf, "-W", "-h", "-l", "-d", str(path)],
                          capture_output=True, text=True, check=True, timeout=15,
                          env={**os.environ, "LC_ALL": "C"})
    if info.stderr:
        raise ValueError("ELF inspection diagnostic: " + info.stderr[:300])
    text = info.stdout
    interps = re.findall(r"Requesting program interpreter: ([^\]]+)\]", text)
    needed = re.findall(r"\(NEEDED\).*?Shared library: \[([^\]]+)\]", text)
    sonames = re.findall(r"\(SONAME\).*?Library soname: \[([^\]]+)\]", text)
    if len(interps) > 1 or len(sonames) > 1 or len(needed) != len(set(needed)):
        raise ValueError("Ambiguous ELF dynamic metadata")
    if any(not re.fullmatch(r"[A-Za-z0-9_.+-]+\.so", name) for name in needed + sonames):
        raise ValueError("Unexpected dependency name")
    if re.search(r"\((?:RPATH|RUNPATH)\)", text):
        raise ValueError("Unexpected embedded library search path")
    if hashlib.sha256(path.read_bytes()).digest() != hashlib.sha256(data).digest():
        raise ValueError("ELF changed during inspection")
    return {"sha256": hashlib.sha256(data).hexdigest(), "size_bytes": len(data),
            "elf_type": int.from_bytes(data[16:18], "little"),
            "interpreter": interps[0] if interps else None,
            "needed": needed, "soname": sonames[0] if sonames else None}


def validate_probe(info: dict) -> None:
    if info["elf_type"] != 3 or info["interpreter"] != INTERP:
        raise ValueError("Expected Android PIE with /system/bin/linker64")
    if not {"libc.so", "libdl.so"} <= set(info["needed"]) <= set(LIBS):
        raise ValueError("Unexpected Android probe dependencies")


def runtime_file(root: Path, relative: str) -> Path:
    path = root / relative
    if path.resolve() != path.absolute():
        raise ValueError("Symlinked runtime component: " + relative)
    return path


def inventory(probe: Path, root: Path | None, readelf: str) -> dict:
    info = inspect_elf(probe, readelf)
    validate_probe(info)
    result = {"status": "DYNAMIC_PROBE_STATIC_ONLY", "probe": info,
              "android_api_target": 30, "dynamic_android_linker_tested": False,
              "android_boot_tested": False, "safe_to_flash": False}
    if root is None:
        return result
    root = root.resolve(strict=True)
    linker = inspect_elf(runtime_file(root, RUNTIME + "/bin/linker64"), readelf)
    if linker["elf_type"] != 3 or linker["interpreter"] is not None or linker["needed"]:
        raise ValueError("Expected self-contained Android linker64")
    libraries = {}
    pending = list(info["needed"])
    while pending:
        name = pending.pop()
        if name in libraries:
            continue
        if name not in LIBS:
            raise ValueError("Dependency outside minimal runtime: " + name)
        lib = inspect_elf(runtime_file(root, RUNTIME + "/lib64/bionic/" + name), readelf)
        if lib["elf_type"] != 3 or lib["interpreter"] is not None or lib["soname"] != name:
            raise ValueError("Unexpected runtime library identity: " + name)
        libraries[name] = lib
        pending.extend(lib["needed"])
    return {**result, "status": "ANDROID_RUNTIME_INVENTORY_ONLY",
            "linker64": linker, "libraries": libraries,
            "runtime_authenticity_verified": False,
            "runtime_stub_exclusion_proven": False,
            "planned_guest_paths": {INTERP: "/" + RUNTIME + "/bin/linker64",
                                    **{"/" + RUNTIME + "/lib64/bionic/" + name: lib["sha256"]
                                       for name, lib in sorted(libraries.items())}},
            "linkerconfig_required_for_full_android": True}


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--probe", required=True, type=Path)
    p.add_argument("--runtime-root", type=Path)
    p.add_argument("--readelf", default="readelf")
    p.add_argument("--report", required=True, type=Path)
    a = p.parse_args()
    try:
        result = inventory(a.probe, a.runtime_root, a.readelf)
        rc = 0
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        result = {"status": "REJECT", "reason": str(exc),
                  "dynamic_android_linker_tested": False, "safe_to_flash": False}
        rc = 2
    a.report.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(result["status"])
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
