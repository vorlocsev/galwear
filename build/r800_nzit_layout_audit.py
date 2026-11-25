#!/usr/bin/env python3
"""Read-only historical SM-R800 NZIT layout audit, not a signature verifier."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import struct

SCHEMA = "galwear-r800-nzit-layout-v1"
HEADER = 2048
SIGNATURE = 272
HISTORICAL_PARTITION = 18874368
HISTORICAL_SLOT = 133120
HISTORICAL_SLOT_OFFSET = 2048
MAX_TABLE = 4 * 1024 * 1024


class LayoutError(ValueError):
    pass


def aligned(n: int) -> int:
    return (n + HEADER - 1) & ~(HEADER - 1)


def budget(kernel_bytes: int, table_bytes: int) -> dict:
    if not 64 <= kernel_bytes <= HISTORICAL_PARTITION:
        raise LayoutError("Kernel size outside historical partition bounds")
    if not 12 <= table_bytes <= MAX_TABLE:
        raise LayoutError("EXYN table size outside bounds")
    used = HEADER + aligned(kernel_bytes) + table_bytes + SIGNATURE
    return {"kernel_bytes": kernel_bytes, "table_bytes": table_bytes,
            "container_unpadded_bytes": used,
            "historical_partition_bytes": HISTORICAL_PARTITION,
            "remaining_bytes": HISTORICAL_PARTITION - used,
            "fits_historical_partition": used <= HISTORICAL_PARTITION}


def read_bounded(path: Path, limit: int) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise LayoutError("Input missing or symlinked")
    with path.open("rb") as stream:
        data = stream.read(limit + 1)
    if not data or len(data) > limit:
        raise LayoutError("Input size outside audit bounds")
    return data


def kernel_header(data: bytes) -> dict:
    if len(data) < 64 or data[56:60] != b"ARM\x64":
        raise LayoutError("Missing ARM64 Image header")
    offset, size, flags = struct.unpack_from("<QQQ", data, 8)
    if not size or flags & 1:
        raise LayoutError("Unsupported ARM64 Image size or endianness")
    return {"text_offset": offset, "runtime_image_size": size, "flags": flags,
            "sha256": hashlib.sha256(data).hexdigest()}


def fdt_header(data: bytes) -> dict:
    if len(data) < 40:
        raise LayoutError("Truncated FDT header")
    magic, total, off_struct, off_strings, off_rsv, ver, last, _, len_strings, len_struct = (
        struct.unpack_from(">10I", data))
    if magic != 0xd00dfeed or not 40 <= total <= len(data):
        raise LayoutError("Invalid FDT magic or total size")
    if ver != 17 or last > ver or last > 17:
        raise LayoutError("Unsupported FDT version")
    if off_rsv < 40 or off_rsv % 8 or off_struct % 4 or len_struct < 4:
        raise LayoutError("Invalid FDT block alignment")
    if not (off_rsv + 16 <= off_struct <= off_struct + len_struct <= off_strings
            <= off_strings + len_strings <= total):
        raise LayoutError("FDT blocks overlap or exceed declared bounds")
    for pos in range(off_rsv, off_struct - 15, 16):
        if data[pos:pos + 16] == bytes(16):
            break
    else:
        raise LayoutError("FDT reserve map has no terminator")
    return {"fdt_totalsize": total, "fdt_version": ver,
            "sha256": hashlib.sha256(data).hexdigest()}


def table_layout(table: bytes) -> dict:
    if len(table) < 12:
        raise LayoutError("Truncated EXYN table")
    magic, version, count = struct.unpack_from("<3I", table)
    if magic != 0x4e595845 or not 1 <= count <= 64 or 12 + count * 20 > len(table):
        raise LayoutError("Invalid EXYN table header")
    entries, selectors, slots = [], set(), {}
    for i in range(count):
        platform, variant, rev, offset, size = struct.unpack_from("<5I", table, 12 + i * 20)
        key = (platform, variant, rev)
        if key in selectors:
            raise LayoutError("Duplicate EXYN selector")
        selectors.add(key)
        if offset % 4 or offset < 12 + count * 20 or not size or offset + size > len(table):
            raise LayoutError("EXYN DTB slot out of bounds or unaligned")
        slot = (offset, offset + size)
        if slot not in slots:
            for start, end in slots:
                if offset < end and start < offset + size:
                    raise LayoutError("Partially overlapping EXYN DTB slots")
            slots[slot] = fdt_header(table[offset:offset + size])
        entries.append({"platform": platform, "variant": variant, "revision": rev,
                        "offset": offset, "size": size})
    historical = (count == 6 and len(slots) == 1 and
                  (HISTORICAL_SLOT_OFFSET, HISTORICAL_SLOT_OFFSET + HISTORICAL_SLOT) in slots)
    return {"version": version, "entries": entries, "unique_slots": len(slots),
            "historical_shared_slot_matches": historical,
            "slots": [{"offset": a, "size": b - a, **info} for (a, b), info in slots.items()]}


def inspect_template(path: Path) -> dict:
    data = read_bounded(path, HISTORICAL_PARTITION)
    if len(data) < HEADER + SIGNATURE:
        raise LayoutError("Truncated NZIT container")
    magic, alignment, ksize, total, dt_size, ramdisk, hsize = struct.unpack_from("<7I", data)
    if magic != 0x54495a4e or hsize != HEADER or not alignment or alignment & (alignment - 1):
        raise LayoutError("Invalid NZIT header")
    capacity = budget(ksize, dt_size)
    end = capacity["container_unpadded_bytes"]
    if end > len(data):
        raise LayoutError("NZIT component bounds exceed file")
    dt_start = HEADER + aligned(ksize)
    dt_end = dt_start + dt_size
    if any(data[HEADER + ksize:dt_start]):
        raise LayoutError("Nonzero kernel alignment padding")
    if any(data[end:]):
        raise LayoutError("Unexpected nonzero partition tail")
    table = table_layout(data[dt_start:dt_end])
    return {"sha256": hashlib.sha256(data).hexdigest(), "size_bytes": len(data),
            "alignment_field": alignment, "total_kernel_field": total,
            "ramdisk_field": ramdisk, "kernel": kernel_header(data[HEADER:HEADER + ksize]),
            "table": table, "budget": capacity,
            "signature_bytes": SIGNATURE, "signature_sha256": hashlib.sha256(data[dt_end:end]).hexdigest(),
            "signature_verified": False}


def audit(image: Path, dtb: Path, template: Path | None = None) -> dict:
    raw = read_bounded(image, HISTORICAL_PARTITION)
    tree = read_bounded(dtb, HISTORICAL_SLOT)
    if len(tree) != HISTORICAL_SLOT:
        raise LayoutError("DTB does not match historical slot size")
    dt = fdt_header(tree)
    if dt["fdt_totalsize"] != HISTORICAL_SLOT:
        raise LayoutError("DTB totalsize does not match slot")
    reference = inspect_template(template) if template else None
    table_size = reference["budget"]["table_bytes"] if reference else HISTORICAL_SLOT_OFFSET + HISTORICAL_SLOT
    capacity = budget(len(raw), table_size)
    blockers = ["RETAIL_PIT_CAPACITY_UNVERIFIED", "SBOOT_SIGNATURE_AND_DTB_SELECTION_UNVERIFIED",
                "DEVICE_RECOVERY_UNVERIFIED"]
    if reference is None:
        blockers.append("REFERENCE_NZIT_NOT_PROVIDED_TABLE_SIZE_ASSUMED")
    elif not reference["table"]["historical_shared_slot_matches"]:
        blockers.append("REFERENCE_EXYN_LAYOUT_DIFFERS_FROM_HISTORICAL_PACKER")
    if not capacity["fits_historical_partition"]:
        blockers.append("HISTORICAL_PARTITION_OVERFLOW")
    return {"schema": SCHEMA, "status": "STATIC_LAYOUT_ONLY", "kernel": kernel_header(raw),
            "dtb": dt, "budget": capacity, "reference": reference, "boot_blockers": blockers,
            "firmware_built": False, "signature_verified": False, "safe_to_flash": False}


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--image", type=Path, required=True)
    p.add_argument("--dtb", type=Path, required=True)
    p.add_argument("--template", type=Path)
    p.add_argument("--report", type=Path, required=True)
    a = p.parse_args()
    try:
        result = audit(a.image, a.dtb, a.template)
        rc = 0 if result["budget"]["fits_historical_partition"] else 2
    except (ValueError, OSError, struct.error) as exc:
        result = {"schema": SCHEMA, "status": "REJECT", "reason": str(exc),
                  "firmware_built": False, "safe_to_flash": False}
        rc = 2
    a.report.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(result["status"])
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
