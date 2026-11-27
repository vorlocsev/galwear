#!/usr/bin/env python3
"""Hash-only diagnostics for independent non-release kernel builds."""
import argparse
import hashlib
import json
from pathlib import Path
import struct

BLOCK = 65536
MAX_FILE = 512 * 1024 * 1024


def digest(data):
    return hashlib.sha256(data).hexdigest()


def read(path):
    if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= MAX_FILE:
        raise ValueError("Invalid diagnostic input: " + path.name)
    return path.read_bytes()


def sections(data):
    if data[:6] != b"\x7fELF\x02\x01" or len(data) < 64:
        raise ValueError("Expected little-endian ELF64")
    if struct.unpack_from("<H", data, 18)[0] != 183:
        raise ValueError("Expected AArch64 vmlinux")
    off = struct.unpack_from("<Q", data, 40)[0]
    entsize, count, names = struct.unpack_from("<HHH", data, 58)
    if entsize != 64 or not 0 < count <= 4096 or names >= count or off + count * entsize > len(data):
        raise ValueError("Invalid section table")
    rows = [struct.unpack_from("<IIQQQQIIQQ", data, off + i * entsize) for i in range(count)]
    def payload(row):
        start, size = row[4:6]
        if start + size > len(data):
            raise ValueError("Section outside ELF")
        return data[start:start + size]
    strings = payload(rows[names])
    result = {}
    for row in rows:
        name, kind, flags, address, _, size = row[:6]
        if not flags & 2 or kind == 8:  # allocatable file-backed sections
            continue
        end = strings.find(b"\0", name)
        if end < 0:
            raise ValueError("Invalid section name")
        key = strings[name:end].decode("ascii")
        if not key or key in result:
            raise ValueError("Empty or duplicate section name")
        result[key] = {"address": address, "bytes": size, "sha256": digest(payload(row))}
    if not result:
        raise ValueError("No allocatable sections")
    return result


def snapshot(root):
    image = read(root / "arch/arm64/boot/Image")
    if image[56:60] != b"ARM\x64":
        raise ValueError("Invalid ARM64 Image")
    elf = read(root / "vmlinux")
    return {
        "schema": "galwear-kernel-diagnostic-v1",
        "image_sha256": digest(image),
        "image_bytes": len(image),
        "block_bytes": BLOCK,
        "blocks": [digest(image[i:i+BLOCK]) for i in range(0, len(image), BLOCK)],
        "sections": sections(elf),
        "safe_to_flash": False,
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--root", required=True, type=Path)
    p.add_argument("--output", required=True, type=Path)
    a = p.parse_args()
    with a.output.open("x", encoding="utf-8") as f:
        json.dump(snapshot(a.root), f, indent=2, sort_keys=True)
        f.write("\n")


if __name__ == "__main__":
    main()
