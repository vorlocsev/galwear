#!/usr/bin/env python3
"""Inspect analyst-selected GPS HAL tables in ARM32 ET_DYN files, offline only."""
import argparse
import hashlib
import json
from pathlib import Path
import struct

LIMIT = 64 * 1024**2
LAYOUTS = {
    "gps": ("init", "start", "stop", "cleanup", "inject_time", "inject_location",
            "delete_aiding_data", "set_position_mode", "get_extension"),
    "xtra": ("init", "inject_xtra_data"),
}
# Only ordinary ELF32 REL tables are supported. Other encodings fail closed.
DENIED = {7, 8, 9, 35, 36, 37, 0x6000000f, 0x60000010, 0x60000011,
          0x60000012, 0x6fffe000, 0x6fffe001, 0x6fffe003}


def audit(raw, address, layout):
    if layout not in LAYOUTS or type(address) is not int or not 0 <= address <= 0xffffffff or address % 4:
        raise ValueError("Invalid table address or layout")
    if len(raw) < 52 or len(raw) > LIMIT or raw[:7] != b"\x7fELF\x01\x01\x01":
        raise ValueError("Expected bounded little-endian ELF32")
    etype, machine, version = struct.unpack_from("<HHI", raw, 16)
    phoff, flags = struct.unpack_from("<I4xI", raw, 28)
    ehsize, entsize, count = struct.unpack_from("<HHH", raw, 40)
    if (etype, machine, version) != (3, 40, 1) or flags & 0xff000400 != 0x05000000:
        raise ValueError("Expected ARM EABI5 shared object without hard-float flag")
    if ehsize != 52 or entsize != 32 or not 1 <= count <= 128 or phoff + 32 * count > len(raw):
        raise ValueError("Invalid program header table")
    loads, dynamic = [], []
    for i in range(count):
        typ, off, va, _, fs, ms, pf, _ = struct.unpack_from("<8I", raw, phoff + 32 * i)
        if typ not in (1, 2):
            continue
        if fs > ms or off + fs > len(raw) or va + ms > 2**32:
            raise ValueError("Invalid segment bounds")
        (loads if typ == 1 else dynamic).append((va, off, fs, ms, pf))

    def mapping(va, size):
        hits = [(off + va - start, pf) for start, off, fs, _, pf in loads
                if start <= va and 0 < size <= fs - (va - start)]
        if len(hits) != 1:
            raise ValueError("Address not uniquely file-backed")
        return hits[0]

    if len(dynamic) != 1:
        raise ValueError("Expected one PT_DYNAMIC")
    va, off, size, _, _ = dynamic[0]
    if size % 8 or not 1 <= size // 8 <= 8192 or mapping(va, size)[0] != off:
        raise ValueError("Invalid dynamic table")
    tags = {}
    for p in range(off, off + size, 8):
        tag, value = struct.unpack_from("<II", raw, p)
        if tag == 0:
            break
        tags.setdefault(tag, []).append(value)
    else:
        raise ValueError("Missing DT_NULL")
    if DENIED.intersection(tags):
        raise ValueError("Unsupported relocation encoding")

    def one(tag):
        if len(tags.get(tag, [])) != 1:
            raise ValueError("Missing or duplicate relocation tag")
        return tags[tag][0]

    tables = []
    if any(t in tags for t in (17, 18, 19)):
        if one(19) != 8:
            raise ValueError("Invalid DT_RELENT")
        tables.append((one(17), one(18)))
    if any(t in tags for t in (2, 20, 23)):
        if one(20) != 17:
            raise ValueError("Expected REL PLT")
        tables.append((one(23), one(2)))
    relocations, ranges = {}, []
    total = 0
    for va, size in tables:
        total += size // 8
        if size % 8 or total > 131072:
            raise ValueError("Invalid relocation count")
        if not size:
            continue
        off, _ = mapping(va, size)
        if any(off < end and start < off + size for start, end in ranges):
            raise ValueError("Overlapping relocation tables")
        ranges.append((off, off + size))
        for p in range(off, off + size, 8):
            target, info = struct.unpack_from("<II", raw, p)
            typ, sym = info & 255, info >> 8
            if typ == 0:
                continue
            if typ not in (2, 3, 21, 22, 23) or target % 4 or target in relocations or (typ == 23 and sym):
                raise ValueError("Unsupported or ambiguous relocation record")
            if not any(start <= target and 4 <= ms - (target - start) for start, _, _, ms, _ in loads):
                raise ValueError("Relocation outside load memory")
            relocations[target] = (typ, sym)
    fields = LAYOUTS[layout]
    required = 4 * (1 + len(fields))
    off, pf = mapping(address, required)
    declared, = struct.unpack_from("<I", raw, off)
    if not pf & 4 or pf & 1 or declared < required or declared > 4096 or declared % 4 or address in relocations:
        raise ValueError("Invalid interface table header")
    mapping(address, declared)
    entries = []
    for index, field in enumerate(fields, 1):
        slot = address + 4 * index
        value, = struct.unpack_from("<I", raw, off + 4 * index)
        relocation = relocations.get(slot)
        row = {"field": field, "slot_va": slot, "raw_word": value,
               "relocation": relocation, "target_va": None, "isa": None,
               "status": "UNRESOLVED"}
        if relocation == (23, 0) and value:
            target, isa = value & ~1, "thumb" if value & 1 else "arm"
            try:
                _, target_flags = mapping(target, 2 if isa == "thumb" else 4)
                if target % (2 if isa == "thumb" else 4) == 0 and target_flags & 1 and not target_flags & 2:
                    row.update(target_va=target, isa=isa, status="RELATIVE_EXECUTABLE_CANDIDATE")
            except ValueError:
                pass
        elif relocation is None and value == 0:
            row["status"] = "NULL_WORD"
        entries.append(row)
    return {"schema": "galwear-r800-gps-interface-table-v1", "status": "STATIC_TABLE_CLUES_ONLY",
            "sha256": hashlib.sha256(raw).hexdigest(), "layout_assumption": layout,
            "table_va": address, "declared_size": declared, "entries": entries,
            "table_identity_verified": False, "relocations_applied": False,
            "instruction_targets_verified": False, "callback_layout_verified": False,
            "selected_abi": None, "runtime_verified": False, "safe_to_flash": False}


def main():
    from r800_android_userspace_preflight import read_regular
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--library", type=Path, required=True)
    parser.add_argument("--table-va", type=lambda s: int(s, 0), required=True)
    parser.add_argument("--layout", choices=LAYOUTS, required=True)
    args = parser.parse_args()
    try:
        report = audit(read_regular(args.library, LIMIT), args.table_va, args.layout)
    except (OSError, ValueError, struct.error) as exc:
        report = {"status": "REVIEW_REQUIRED", "error": str(exc), "safe_to_flash": False}
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["status"] == "STATIC_TABLE_CLUES_ONLY" else 2


if __name__ == "__main__":
    raise SystemExit(main())
