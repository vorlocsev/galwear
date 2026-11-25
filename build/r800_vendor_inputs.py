#!/usr/bin/env python3
"""Read-only validation of explicit local vendor build inputs."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import stat

from r800_android_userspace_preflight import read_regular
from r800_android_linker_audit import inspect

MAX_IMAGE = 4 * 1024**3
MAX_LIBRARY = 64 * 1024**2
OVERLAY = ("etc/init/init.r800.rc", "etc/fstab.r800", "ueventd.rc",
           "etc/vintf/manifest.xml", "hwcomposer.r800.so", "lights.r800.so")


def checked_file(path, maximum):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= maximum:
        raise ValueError("Expected bounded regular file: " + str(path))
    return info


def image_info(path):
    info = checked_file(path, MAX_IMAGE)
    h = hashlib.sha256()
    with path.open("rb") as stream:
        head = stream.read(2048)
        if len(head) < 1082 or head[1080:1082] != b"\x53\xef":
            raise ValueError("Expected raw ext4 donor image: " + str(path))
        h.update(head)
        count = len(head)
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
            count += len(block)
            if count > info.st_size:
                raise ValueError("Donor size changed")
    if count != info.st_size or path.stat().st_mtime_ns != info.st_mtime_ns:
        raise ValueError("Donor changed during hashing")
    return {"bytes": count, "sha256": h.hexdigest(), "ext4_magic": True}


def file_info(path, library=False):
    checked_file(path, MAX_LIBRARY if library else 1024 * 1024)
    raw = read_regular(path, MAX_LIBRARY if library else 1024 * 1024)
    item = {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
    if library:
        elf = inspect(raw)
        if elf["abi"] != "arm" or elf["elf_type"] != "ET_DYN" or not elf["has_dynamic"]:
            raise ValueError("Expected ARM32 shared library: " + str(path))
        item.update({"abi": elf["abi"], "needed": elf["needed"]})
    return item


def audit(base, j4, overlay, effects):
    if not overlay.is_dir() or overlay.is_symlink():
        raise ValueError("Expected local overlay directory")
    overlay = overlay.resolve(strict=True)
    files = {}
    for name in OVERLAY:
        path = overlay / name
        if path.resolve(strict=True) != path:
            raise ValueError("Symlink in overlay path: " + name)
        files[name] = file_info(path, name.endswith(".so"))
    return {"status": "VENDOR_INPUT_STRUCTURE_ONLY",
            "base_vendor": image_info(base), "j4_vendor": image_info(j4),
            "overlay": files, "effects": file_info(effects, True),
            "donor_authenticity_verified": False,
            "hal_runtime_verified": False, "safe_to_flash": False}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ("base", "j4", "overlay", "effects"):
        p.add_argument("--" + name, type=Path, required=True)
    args = p.parse_args()
    print(json.dumps(audit(args.base, args.j4, args.overlay, args.effects),
                     indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
