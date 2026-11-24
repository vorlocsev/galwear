#!/usr/bin/env python3
"""Offline Android 11 system-as-root structural preflight; never executes guest files."""
from __future__ import annotations

import argparse
from collections import deque
import hashlib
import json
import os
from pathlib import Path
import stat
import struct

REQUIRED_CONFIG = {
    "CONFIG_ARM64": "y", "CONFIG_COMPAT": "y", "CONFIG_BINFMT_ELF": "y",
    "CONFIG_ANDROID_BINDER_IPC": "y",
    "CONFIG_ANDROID_BINDER_DEVICES": '"binder,hwbinder,vndbinder"',
    "CONFIG_BLK_DEV_LOOP": "y", "CONFIG_EXT4_FS": "y",
    "CONFIG_TMPFS": "y", "CONFIG_DEVTMPFS": "y", "CONFIG_CGROUPS": "y",
    "CONFIG_NAMESPACES": "y", "CONFIG_SECCOMP_FILTER": "y",
    "CONFIG_SECURITY_SELINUX": "y",
}
MAX_CONFIG = 1024 * 1024
MAX_ELF = 64 * 1024 * 1024


def guest_path(root: Path, name: str) -> Path:
    """Resolve Android symlinks relative to guest root, never host root."""
    root = root.resolve(strict=True)
    pending = deque(name.split("/"))
    parts = []
    links = 0
    while pending:
        item = pending.popleft()
        if item in ("", "."):
            continue
        if item == "..":
            if not parts:
                raise ValueError("Path escapes guest root")
            parts.pop()
            continue
        candidate = root.joinpath(*parts, item)
        mode = candidate.lstat().st_mode
        if stat.S_ISLNK(mode):
            links += 1
            if links > 40:
                raise ValueError("Guest symlink loop")
            target = os.readlink(candidate)
            if target.startswith("/"):
                parts.clear()
            pending.extendleft(reversed(target.split("/")))
        else:
            parts.append(item)
            if pending and not stat.S_ISDIR(mode):
                raise ValueError("Non-directory in guest path")
    return root.joinpath(*parts)


def read_regular(path: Path, limit: int) -> bytes:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= limit:
        raise ValueError("Expected bounded regular file")
    with path.open("rb") as stream:
        data = stream.read(limit + 1)
    if len(data) != info.st_size or len(data) > limit:
        raise ValueError("File changed while reading")
    return data


def config_check(path: Path) -> dict:
    data = read_regular(path, MAX_CONFIG)
    values = {}
    for line in data.decode("utf-8").splitlines():
        if line.startswith("CONFIG_") and "=" in line:
            key, value = line.split("=", 1)
            if key in values:
                raise ValueError("Duplicate config key: " + key)
            values[key] = value
        elif line.startswith("# CONFIG_") and line.endswith(" is not set"):
            key = line[2:-11]
            if key in values:
                raise ValueError("Duplicate config key: " + key)
            values[key] = "n"
    missing = {k: {"expected": v, "actual": values.get(k)}
               for k, v in REQUIRED_CONFIG.items() if values.get(k) != v}
    return {"sha256": hashlib.sha256(data).hexdigest(), "missing_or_wrong": missing}


def elf_check(root: Path, name: str) -> dict:
    path = guest_path(root, name)
    data = read_regular(path, MAX_ELF)
    if len(data) < 52 or data[:4] != b"\x7fELF" or data[5:7] != b"\x01\x01":
        raise ValueError("Not little-endian ELF")
    cls = data[4]
    if cls not in (1, 2) or (cls == 2 and len(data) < 64):
        raise ValueError("Invalid ELF class")
    etype, machine = struct.unpack_from("<HH", data, 16)
    if etype not in (2, 3) or (cls, machine) not in ((1, 40), (2, 183)):
        raise ValueError("Expected ARM or AArch64 executable")
    if not path.stat().st_mode & 0o111:
        raise ValueError("Not executable")
    if cls == 2:
        entry, phoff = struct.unpack_from("<QQ", data, 24)
        entsize, count = struct.unpack_from("<HH", data, 54)
        expected = 56
    else:
        entry, phoff = struct.unpack_from("<II", data, 24)
        entsize, count = struct.unpack_from("<HH", data, 42)
        expected = 32
    if not entry or not 1 <= count <= 128 or entsize != expected or phoff + count * entsize > len(data):
        raise ValueError("Invalid executable program headers")
    interpreter = None
    loads = 0
    for index in range(count):
        p = phoff + index * entsize
        typ = struct.unpack_from("<I", data, p)[0]
        off, size = (struct.unpack_from("<Q", data, p + 8)[0], struct.unpack_from("<Q", data, p + 32)[0]) if cls == 2 else (struct.unpack_from("<I", data, p + 4)[0], struct.unpack_from("<I", data, p + 16)[0])
        if typ in (1, 3) and off + size > len(data):
            raise ValueError("Segment exceeds file")
        if typ == 1:
            loads += 1
        if typ == 3:
            if interpreter is not None or not 2 <= size <= 4096:
                raise ValueError("Invalid interpreter segment")
            raw = data[off:off + size]
            if not raw.endswith(b"\0") or b"\0" in raw[:-1]:
                raise ValueError("Invalid interpreter string")
            interpreter = raw[:-1].decode("ascii")
            if not interpreter.startswith("/"):
                raise ValueError("Nonabsolute guest interpreter")
    if not loads:
        raise ValueError("No LOAD segments")
    return {"architecture": "arm64" if cls == 2 else "arm",
            "sha256": hashlib.sha256(data).hexdigest(), "interpreter": interpreter}


def audit(root: Path, config: Path) -> dict:
    checks = config_check(config)
    errors = []
    binaries = {}
    for name in ("/init", "/system/bin/servicemanager", "/system/bin/hwservicemanager",
                 "/vendor/bin/vndservicemanager", "/system/bin/app_process32"):
        try:
            info = elf_check(root, name)
            if info["interpreter"]:
                linker = elf_check(root, info["interpreter"])
                if linker["architecture"] != info["architecture"] or linker["interpreter"]:
                    raise ValueError("Incompatible guest linker")
            binaries[name] = info
        except (OSError, ValueError) as exc:
            errors.append(name + ": " + str(exc))
    for name in ("/system/etc/init", "/vendor/etc/init"):
        try:
            if not guest_path(root, name).is_dir():
                raise ValueError("Not a directory")
        except (OSError, ValueError) as exc:
            errors.append(name + ": " + str(exc))
    ok = not errors and not checks["missing_or_wrong"]
    return {"schema": "galwear-r800-android-structure-v1",
            "status": "STATIC_USERSPACE_PREFLIGHT_PASS" if ok else "REJECT_USERSPACE_PREFLIGHT",
            "kernel_config": checks, "binaries": binaries, "errors": errors,
            "android_boot_tested": False, "selinux_policy_validated": False,
            "hal_compatibility_validated": False, "safe_to_flash": False}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--root", type=Path, required=True)
    p.add_argument("--config", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    if args.output.resolve().is_relative_to(args.root.resolve()):
        p.error("Report must be outside the guest root")
    try:
        result = audit(args.root, args.config)
    except (OSError, ValueError) as exc:
        result = {"status": "REJECT_USERSPACE_PREFLIGHT", "errors": [str(exc)],
                  "safe_to_flash": False}
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(result["status"])
    return 0 if result["status"] == "STATIC_USERSPACE_PREFLIGHT_PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
