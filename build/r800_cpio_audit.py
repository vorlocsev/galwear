#!/usr/bin/env python3
"""Read-only newc CPIO archive audit for experimental R800 embedded /init.

This checks content only; it does not boot an image or prove recovery. The
kernel Image and CPIO are never published by the CI workflow.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path
import sys
import zlib

from r800_initramfs_spec import validate_init

MAX_ARCHIVE_BYTES = 32 * 1024 * 1024
MAX_ENTRY_COUNT = 64
EXPECTED = {
    "dev": (0o040000, 0o755),
    "dev/console": (0o020000, 0o600),
    "proc": (0o040000, 0o555),
    "sys": (0o040000, 0o555),
    "data": (0o040000, 0o755),
    "init": (0o100000, 0o755),
}


class CpioError(ValueError):
    pass


def _read_archive(path: Path) -> tuple[bytes, str]:
    if path.is_symlink() or not path.is_file():
        raise CpioError("CPIO archive missing or symlinked")
    # Hash the exact bounded snapshot that is parsed, not a second read.
    with path.open("rb") as f:
        raw = f.read(MAX_ARCHIVE_BYTES + 1)
    if not raw or len(raw) > MAX_ARCHIVE_BYTES:
        raise CpioError("CPIO input size is out of bounds")
    if raw.startswith(b"\x1f\x8b"):
        with gzip.GzipFile(fileobj=io.BytesIO(raw)) as gz:
            data = gz.read(MAX_ARCHIVE_BYTES + 1)
    else:
        data = raw
    if not data or len(data) > MAX_ARCHIVE_BYTES:
        raise CpioError("CPIO uncompressed size is out of bounds")
    return data, hashlib.sha256(raw).hexdigest()


def _aligned(value: int) -> int:
    return (value + 3) & ~3


def inspect_cpio(archive: Path, init_binary: Path) -> dict:
    elf = validate_init(init_binary)
    content, archive_sha256 = _read_archive(archive)
    pos = 0
    names = {}
    count = 0
    saw_trailer = False
    while pos < len(content):
        if pos + 110 > len(content) or content[pos:pos + 6] not in (b"070701", b"070702"):
            raise CpioError("Invalid newc CPIO magic/header")
        fields = []
        try:
            for i in range(13):
                field = content[pos + 6 + i * 8:pos + 14 + i * 8]
                if any(c not in b"0123456789abcdefABCDEF" for c in field):
                    raise ValueError("non-hexadecimal field")
                fields.append(int(field, 16))
        except ValueError as exc:
            raise CpioError("Invalid newc hexadecimal header") from exc
        mode = fields[1]
        length = fields[6]
        name_length = fields[11]
        if not 1 <= name_length <= 1024 or length > MAX_ARCHIVE_BYTES:
            raise CpioError("Invalid newc entry sizes")
        name_pos = pos + 110
        if name_pos + name_length > len(content):
            raise CpioError("Truncated newc pathname")
        raw_name = content[name_pos:name_pos + name_length]
        if not raw_name.endswith(b"\x00") or b"\x00" in raw_name[:-1]:
            raise CpioError("CPIO filename is not NUL terminated")
        try:
            name = raw_name[:-1].decode("ascii")
        except UnicodeDecodeError as exc:
            raise CpioError("Non-ASCII CPIO filename") from exc
        data_pos = _aligned(name_pos + name_length)
        end = data_pos + length
        next_pos = _aligned(end)
        if next_pos > len(content):
            raise CpioError("Truncated newc file data or padding")
        if any(content[name_pos + name_length:data_pos]) or any(content[end:next_pos]):
            raise CpioError("Nonzero newc alignment padding")
        if content[pos:pos + 6] == b"070702":
            if fields[12] != sum(content[data_pos:end]) & 0xffffffff:
                raise CpioError("Invalid CPIO CRC checksum")
        elif fields[12] != 0:
            raise CpioError("Unexpected checksum in non-CRC CPIO entry")
        if name == "TRAILER!!!":
            if length != 0:
                raise CpioError("CPIO trailer carries unexpected data")
            saw_trailer = True
            if any(v != 0 for v in content[_aligned(end):]):
                raise CpioError("Unexpected trailing CPIO payload")
            break
        if name.startswith("/") or name.startswith("./") or ".." in name.split("/") or name not in EXPECTED:
            raise CpioError(f"Unexpected CPIO entry: {name!r}")
        if name in names:
            raise CpioError(f"Duplicate CPIO entry: {name}")
        expected_type, expected_perms = EXPECTED[name]
        if mode & 0o170000 != expected_type:
            raise CpioError(f"Wrong CPIO file type: {name}")
        if mode & 0o7777 != expected_perms:
            raise CpioError(f"Wrong CPIO permissions: {name}")
        if fields[2] or fields[3]:
            raise CpioError("Unexpected nonroot CPIO owner")
        if name == "dev/console" and (fields[9], fields[10]) != (5, 1):
            raise CpioError("Unexpected /dev/console device major/minor")
        if name == "dev/console" and "dev" not in names:
            raise CpioError("CPIO console appears before parent directory")
        if name == "init":
            if fields[4] != 1:
                raise CpioError("Embedded /init must have exactly one link")
            if hashlib.sha256(content[data_pos:end]).hexdigest() != elf["sha256"]:
                raise CpioError("Embedded /init differs from validated ELF")
            if length != elf["size_bytes"]:
                raise CpioError("Embedded /init size differs from validated ELF")
        elif length != 0:
            raise CpioError(f"Unexpected content in CPIO device/directory: {name}")
        names[name] = {"mode": mode, "size_bytes": length}
        pos = next_pos
        count += 1
        if count > MAX_ENTRY_COUNT:
            raise CpioError("Too many CPIO entries")
    if not saw_trailer:
        raise CpioError("Missing newc CPIO trailer")
    if set(names) != set(EXPECTED):
        raise CpioError("CPIO does not contain exactly six expected entries")
    return {
        "schema": "galwear-r800-cpio-audit-v1",
        "status": "SYNTHETIC_STRUCTURE_PASS_ONLY",
        "entries_checked": count,
        "archive_sha256": archive_sha256,
        "embedded_init_sha256": elf["sha256"],
        "embedded_init_exact_match": True,
        "kernel_boot_tested": False,
        "safe_to_flash": False,
    }


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Read-only generated CPIO /init comparison")
    p.add_argument("--archive", type=Path, required=True)
    p.add_argument("--init", type=Path, required=True)
    p.add_argument("--report", type=Path, required=True)
    a = p.parse_args(argv)
    try:
        result = inspect_cpio(a.archive, a.init)
        status = 0
    except (CpioError, OSError, ValueError, EOFError, zlib.error) as exc:
        result = {
            "schema": "galwear-r800-cpio-audit-v1",
            "status": "REJECT",
            "reason": str(exc),
            "kernel_boot_tested": False,
            "safe_to_flash": False,
        }
        status = 2
    a.report.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n",
                        encoding="utf-8")
    print(result["status"])
    return status


if __name__ == "__main__":
    raise SystemExit(main())
