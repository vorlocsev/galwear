#!/usr/bin/env python3
"""Validate a local experimental AArch64 /init ELF and prepare gen_init_cpio list.

No compiler invocation, devices, mounts, network access or firmware packaging.
The output is a NON-RELEASE kernel initramfs specification. ELF checks are
structural, not an authenticity or runtime safety check.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys

SCHEMA = "galwear-r800-initramfs-smoke-v1"
ELF_MAGIC = b"\x7fELF"
MAX_INIT_BYTES = 2 * 1024 * 1024
PT_LOAD = 1
PT_INTERP = 3
EM_AARCH64 = 183


class InitramfsError(ValueError):
    pass


def validate_init(path: Path) -> dict:
    if not path.is_file() or path.is_symlink():
        raise InitramfsError("Missing or symlinked experimental init binary")
    size = path.stat().st_size
    if not 128 <= size <= MAX_INIT_BYTES:
        raise InitramfsError("Experimental init binary size is out of bounds")
    data = path.read_bytes()
    if (data[:4] != ELF_MAGIC or data[4] != 2 or data[5] != 1 or
            data[6] != 1):
        raise InitramfsError("Expected little-endian ELF64 binary")
    machine = struct.unpack_from("<H", data, 18)[0]
    if machine != EM_AARCH64:
        raise InitramfsError("Expected AArch64 ELF, not host architecture")
    e_type = struct.unpack_from("<H", data, 16)[0]
    if e_type not in (2, 3):
        raise InitramfsError("Experimental init must be executable ELF")
    entry = struct.unpack_from("<Q", data, 24)[0]
    if entry == 0:
        raise InitramfsError("AArch64 ELF has no entry point")
    phoff = struct.unpack_from("<Q", data, 32)[0]
    phentsize, phnum = struct.unpack_from("<HH", data, 54)
    if phnum == 0 or phnum > 128 or phentsize != 56:
        raise InitramfsError("Invalid ELF program header table")
    if phoff + phentsize * phnum > size:
        raise InitramfsError("ELF program headers exceed file size")
    loads = 0
    executable_entry = False
    for i in range(phnum):
        offset = phoff + i * phentsize
        ptype = struct.unpack_from("<I", data, offset)[0]
        if ptype == PT_INTERP:
            raise InitramfsError("Dynamic interpreter is forbidden in static init")
        if ptype == PT_LOAD:
            loads += 1
            flags = struct.unpack_from("<I", data, offset + 4)[0]
            file_offset, vaddr = struct.unpack_from("<QQ", data, offset + 8)
            file_size, mem_size = struct.unpack_from("<QQ", data, offset + 32)
            if file_offset + file_size > size:
                raise InitramfsError("ELF LOAD segment exceeds file size")
            if file_size > mem_size or vaddr + mem_size > 1 << 64:
                raise InitramfsError("Invalid ELF LOAD segment memory size")
            # AArch64 instructions are 4-byte aligned. Require the complete
            # initial instruction to be file-backed in a PF_X segment.
            if flags & 1 and vaddr <= entry and entry + 4 <= vaddr + file_size:
                executable_entry = True
    if not loads:
        raise InitramfsError("AArch64 executable has no loadable segments")
    if entry % 4 or not executable_entry:
        raise InitramfsError("ELF entry must be aligned and inside a file-backed executable LOAD segment")
    return {
        "sha256": hashlib.sha256(data).hexdigest(),
        "size_bytes": size,
        "machine": "AArch64",
        "entry_point": entry,
        "loadable_segments": loads,
        "static_no_interp": True,
    }


def generate_spec(init_binary: Path, out_file: Path) -> dict:
    # Check the supplied path before resolving it, otherwise a symlink could
    # bypass validate_init()'s explicit file-origin check.
    info = validate_init(init_binary)
    image = init_binary.resolve(strict=True)
    # gen_init_cpio's file lines do not support shell quoting; refuse spaces
    # and newlines rather than produce an ambiguous or unsafe archive recipe.
    if any(c.isspace() for c in str(image)):
        raise InitramfsError("Init binary path cannot contain whitespace")
    content = (
        "dir /dev 0755 0 0\n"
        "nod /dev/console 0600 0 0 c 5 1\n"
        "dir /proc 0555 0 0\n"
        "dir /sys 0555 0 0\n"
        "dir /data 0755 0 0\n"
        f"file /init {image} 0755 0 0\n"
    )
    out_file.write_text(content, encoding="utf-8")
    return {
        "schema": SCHEMA,
        "status": "NON_RELEASE_INITRAMFS_SPEC_ONLY",
        "init": info,
        "entries": ["/dev", "/dev/console", "/proc", "/sys", "/data", "/init"],
        "static_structure_verified": True,
        "kernel_boot_tested": False,
        "image_flashed": False,
        "complete_wearos_initramfs": False,
    }


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Create non-release SM-R800 initramfs list")
    p.add_argument("--init", type=Path, required=True)
    p.add_argument("--list", type=Path, required=True)
    p.add_argument("--report", type=Path, required=True)
    a = p.parse_args(argv)
    try:
        result = generate_spec(a.init, a.list)
    except (OSError, ValueError, InitramfsError) as exc:
        result = {"schema": SCHEMA, "status": "REJECT",
                  "reason": str(exc), "image_flashed": False}
        rc = 2
    else:
        rc = 0
    a.report.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n",
                        encoding="utf-8")
    print(result["status"])
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
