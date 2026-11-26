#!/usr/bin/env python3
"""Find GPS factory range from bounded unversioned ELF32 SYSV symbols."""
import argparse
import json
from pathlib import Path
import struct

from r800_gps_interface_table import parse_elf, LIMIT
from r800_gps_interface_xref import audit as xref, MAX_RANGE

FACTORY = b"gps_get_hardware_interface"
MAX_SYMBOLS = 262144
MAX_STRINGS = 8 * 1024**2


def elf_hash(name):
    value = 0
    for byte in name:
        value = (value << 4) + byte
        high = value & 0xf0000000
        if high:
            value ^= high >> 24
        value &= ~high
    return value


def factory_range(raw):
    mapping, _, tags = parse_elf(raw, include_tags=True)

    def one(tag):
        if len(tags.get(tag, [])) != 1:
            raise ValueError("Missing or duplicate dynamic symbol tag")
        return tags[tag][0]

    if any(t in tags for t in (0x6ffffff0, 0x6ffffffc, 0x6ffffffd, 0x6ffffffe, 0x6fffffff)):
        raise ValueError("Versioned symbols require separate review")
    if 4 not in tags:
        raise ValueError("SYSV hash required; GNU-only symbols not supported")
    if one(11) != 16:
        raise ValueError("Invalid DT_SYMENT")
    hash_va = one(4)
    off, _ = mapping(hash_va, 8)
    buckets, count = struct.unpack_from("<II", raw, off)
    if not 1 <= buckets <= MAX_SYMBOLS or not 1 <= count <= MAX_SYMBOLS:
        raise ValueError("Invalid SYSV hash dimensions")
    off, _ = mapping(hash_va, 8 + 4 * (buckets + count))
    indices = struct.unpack_from(f"<{buckets + count}I", raw, off + 8)
    if any(i >= count for i in indices) or indices[buckets] != 0:
        raise ValueError("Invalid SYSV hash index")
    # Reject cyclic reachable chains before using the lookup result.
    done = {0}
    for head in indices[:buckets]:
        seen = set()
        while head not in done:
            if head in seen:
                raise ValueError("Cyclic SYSV hash chain")
            seen.add(head)
            head = indices[buckets + head]
        done.update(seen)
    size = one(10)
    if not 1 <= size <= MAX_STRINGS:
        raise ValueError("Invalid dynamic string table size")
    off, _ = mapping(one(5), size)
    strings = raw[off:off + size]
    if strings[0] != 0:
        raise ValueError("Invalid dynamic string table")
    off, _ = mapping(one(6), count * 16)
    matches = []
    for i in range(1, count):
        name, value, size, info, other, section = struct.unpack_from("<IIIBBH", raw, off + i * 16)
        if name >= len(strings):
            raise ValueError("Dynamic name outside string table")
        end = strings.find(b"\0", name, min(len(strings), name + 4096))
        if end < 0:
            raise ValueError("Invalid dynamic symbol name")
        if strings[name:end] == FACTORY:
            matches.append((i, value, size, info, other, section))
    if len(matches) != 1:
        raise ValueError("Expected exactly one factory symbol")
    index, value, size, info, other, section = matches[0]
    if info >> 4 not in (1, 2) or info & 15 != 2 or other & 3 not in (0, 3) or not 0 < section < 0xff00:
        raise ValueError("Factory must be a defined visible STT_FUNC")
    head = indices[elf_hash(FACTORY) % buckets]
    while head and head != index:
        head = indices[buckets + head]
    if head != index:
        raise ValueError("Factory absent from SYSV lookup chain")
    isa = "thumb" if value & 1 else "arm"
    start = value & ~1
    align = 2 if isa == "thumb" else 4
    if not start or not 0 < size <= MAX_RANGE or start % align or size % align or start + size > 2**32:
        raise ValueError("Invalid factory symbol range")
    _, flags = mapping(start, size)
    if not flags & 1 or flags & 2:
        raise ValueError("Factory range not executable and nonwritable")
    return {"symbol_index": index, "symbol_name": FACTORY.decode(), "isa": isa,
            "start_va": start, "size": size, "hash_kind": "SYSV"}


def audit(raw):
    symbol = factory_range(raw)
    report = xref(raw, [("factory", symbol["isa"], symbol["start_va"], symbol["size"])])
    report.update(schema="galwear-r800-gps-factory-xref-v1", factory_symbol=symbol,
                  symbol_range_from_metadata=True, function_boundaries_verified=False,
                  factory_signature_verified=False)
    return report


def main():
    from r800_android_userspace_preflight import read_regular
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--library", required=True, type=Path)
    args = parser.parse_args()
    try:
        report = audit(read_regular(args.library, LIMIT))
    except (OSError, ValueError, struct.error) as exc:
        report = {"status": "REVIEW_REQUIRED", "error": str(exc),
                  "selected_abi": None, "safe_to_flash": False}
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["status"] == "STATIC_XREF_CLUES_ONLY" else 2


if __name__ == "__main__":
    raise SystemExit(main())
