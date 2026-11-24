#!/usr/bin/env python3
"""Offline comparison of SM-R800 release boot/recovery against combination firmware.

Does not contact a watch, perform flashing, or modify any firmware images.
A matching combination archive is NOT by itself proof of trusted provenance.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys
import tarfile

from r800_safety import SafetyError, preflight_file

# build/mkrelease.sh copies these files byte-for-byte from combination firmware.
COPIED_FROM_COMBINATION = (
    "sboot.bin",
    "param.bin",
    "dzImage-recovery",
    "ramdisk.img",
    "ramdisk-recovery.img",
    "system-data.img",
    "nad_refer.bin",
    "nad_fw.bin",
)

NZIT_MAGIC = 0x54495A4E
EXYN_MAGIC = 0x4E595845
NZIT_HEADER_SIZE = 2048
RSA_TRAILER_SIZE = 272
MAX_DTB_BYTES = 4 * 1024 * 1024


def _members(archive: tarfile.TarFile, required: tuple[str, ...]) -> dict[str, tarfile.TarInfo]:
    names = set(required)
    found: dict[str, tarfile.TarInfo] = {}
    for member in archive.getmembers():
        if member.name not in names:
            continue
        if member.name in found:
            raise SafetyError(f"Duplicate combination member: {member.name}")
        if not member.isfile() or member.size <= 0:
            raise SafetyError(f"Invalid combination member: {member.name}")
        found[member.name] = member
    missing = names - found.keys()
    if missing:
        raise SafetyError("Missing combination members: " + ", ".join(sorted(missing)))
    return found


def _hash_member(archive: tarfile.TarFile, member: tarfile.TarInfo) -> str:
    h = hashlib.sha256()
    stream = archive.extractfile(member)
    if stream is None:
        raise SafetyError(f"Cannot extract {member.name}")
    with stream:
        while True:
            block = stream.read(1024 * 1024)
            if not block:
                break
            h.update(block)
    return h.hexdigest()


def check_nzit(archive: tarfile.TarFile, member: tarfile.TarInfo) -> dict[str, int]:
    """Validate NZIT layout and DTB ranges, not cryptographic signature validity."""
    stream = archive.extractfile(member)
    if stream is None:
        raise SafetyError(f"Cannot read NZIT image {member.name}")
    with stream:
        header = stream.read(NZIT_HEADER_SIZE)
        if len(header) != NZIT_HEADER_SIZE:
            raise SafetyError(f"Truncated NZIT header: {member.name}")
        magic, page_align, kernel_bytes, _total, dt_bytes, ramdisk_bytes, header_bytes = (
            struct.unpack_from("<7I", header)
        )
        if magic != NZIT_MAGIC or header_bytes != NZIT_HEADER_SIZE:
            raise SafetyError(f"Invalid NZIT header: {member.name}")
        if not kernel_bytes or not (12 <= dt_bytes <= MAX_DTB_BYTES):
            raise SafetyError(f"Implausible NZIT sizes: {member.name}")
        if page_align == 0 or (page_align & (page_align - 1)) != 0:
            raise SafetyError(f"Invalid NZIT page alignment: {member.name}")
        dt_start = header_bytes + ((kernel_bytes + 2047) & ~2047)
        dt_end = dt_start + dt_bytes
        if dt_end + RSA_TRAILER_SIZE > member.size:
            raise SafetyError(f"NZIT data or signature area truncated: {member.name}")
        stream.seek(dt_start)
        table = stream.read(dt_bytes)
        if len(table) != dt_bytes:
            raise SafetyError(f"Cannot read NZIT device tree: {member.name}")
        table_magic, _version, count = struct.unpack_from("<III", table)
        if table_magic != EXYN_MAGIC or not 1 <= count <= 64:
            raise SafetyError(f"Invalid EXYN device-tree table: {member.name}")
        if 12 + count * 20 > dt_bytes:
            raise SafetyError(f"Truncated EXYN entries: {member.name}")
        for idx in range(count):
            _, _, _, offset, size = struct.unpack_from("<5I", table, 12 + 20 * idx)
            if not size or offset < 12 + 20 * count or offset + size > dt_bytes:
                raise SafetyError(f"Out-of-range device-tree entry {idx}: {member.name}")
        return {
            "kernel_bytes": kernel_bytes,
            "dt_bytes": dt_bytes,
            "dtb_entries": count,
            "ramdisk_header_bytes": ramdisk_bytes,
            "file_bytes": member.size,
        }


def audit_release(package: str | Path, combination: str | Path) -> dict:
    """Check archive layout, two NZIT containers and reference-image hashes."""
    package, combination = Path(package), Path(combination)
    preflight_file(package)  # MD5, member allowlist, no forbidden partitions
    result = {
        "package": package.name,
        "combination": combination.name,
        "source_authenticity_verified": False,
        "device_compatibility_verified": False,
        "checks": {},
        "nzit": {},
    }
    try:
        with tarfile.open(package, "r:") as dest, tarfile.open(combination, "r:") as origin:
            required = (*COPIED_FROM_COMBINATION, "dzImage")
            output_members = _members(dest, required)
            base_members = _members(origin, COPIED_FROM_COMBINATION)
            for name in COPIED_FROM_COMBINATION:
                actual = _hash_member(dest, output_members[name])
                expected = _hash_member(origin, base_members[name])
                if actual != expected:
                    raise SafetyError(f"{name} differs from provided combination firmware")
                result["checks"][name] = {"matches_combination_sha256": True, "sha256": actual}
            result["nzit"]["dzImage"] = check_nzit(dest, output_members["dzImage"])
            result["nzit"]["dzImage-recovery"] = check_nzit(dest, output_members["dzImage-recovery"])
    except (OSError, tarfile.TarError) as exc:
        raise SafetyError(f"Cannot examine archive: {exc}") from exc
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Offline SM-R800 boot/recovery image comparison; does NOT flash")
    parser.add_argument("--package", required=True, help="R800-WearOS.tar.md5")
    parser.add_argument("--combination", required=True, help="Samsung R800 combination tar")
    parser.add_argument("--report", help="Optional local JSON report path")
    args = parser.parse_args(argv)
    try:
        report = audit_release(args.package, args.combination)
    except (SafetyError, FileNotFoundError) as exc:
        print(f"[FAIL] {exc}", file=sys.stderr)
        return 2
    data = json.dumps(report, indent=2, sort_keys=True)
    if args.report:
        Path(args.report).write_text(data + "\n", encoding="utf-8")
    print(data)
    print("[PASS] Offline structural/reference comparison only. NOT flash approval.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
