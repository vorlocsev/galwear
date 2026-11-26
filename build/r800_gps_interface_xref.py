#!/usr/bin/env python3
"""Bounded ELF32 GPS table references; no inferred function identity."""
import argparse
import json
from pathlib import Path
import struct

from r800_gps_interface_table import discover, parse_elf, LIMIT

MAX_RANGE = 65536
MAX_REFS = 4096
ROLES = ("factory", "get_extension")


def audit(raw, ranges=()):
    discovery = discover(raw)
    mapping, relocations = parse_elf(raw)
    tables = {r["table_va"]: r for r in discovery["candidates"]}
    relative = {}
    for slot, reloc in relocations.items():
        if reloc != (23, 0):
            continue
        try:
            off, flags = mapping(slot, 4)
        except ValueError:
            continue
        value, = struct.unpack_from("<I", raw, off)
        if value in tables and flags & 4:
            relative[slot] = {"slot_va": slot, "table_va": value,
                              "source_executable": bool(flags & 1)}
    if len(relative) > MAX_REFS:
        raise ValueError("Table reference budget exceeded")
    code = []
    seen = set()
    for role, isa, start, size in ranges:
        align = 4 if isa == "arm" else 2
        if (role not in ROLES or role in seen or isa not in ("arm", "thumb")
                or type(start) is not int or type(size) is not int
                or not 0 <= start <= 0xffffffff or not 0 < size <= MAX_RANGE
                or start % align or size % align or start + size > 2**32):
            raise ValueError("Invalid or repeated code range")
        seen.add(role)
        off, flags = mapping(start, size)
        if not flags & 1 or flags & 2:
            raise ValueError("Code range must be executable and nonwritable")
        pos = 0
        refs = []
        while pos < size:
            va = start + pos
            literal, reg = None, None
            if isa == "arm":
                word, = struct.unpack_from("<I", raw, off + pos)
                width = 4
                if word & 0xff7f0000 == 0xe51f0000:
                    delta = word & 0xfff
                    literal = va + 8 + (delta if word & (1 << 23) else -delta)
                    reg = (word >> 12) & 15
            else:
                word, = struct.unpack_from("<H", raw, off + pos)
                width = 4 if word >> 11 in (0b11101, 0b11110, 0b11111) else 2
                if pos + width > size:
                    raise ValueError("Truncated Thumb instruction candidate")
                if width == 2 and word & 0xf800 == 0x4800:
                    literal = ((va + 4) & ~3) + 4 * (word & 255)
                    reg = (word >> 8) & 7
            touched = range(va & ~3, ((va + width - 1) & ~3) + 1, 4)
            if (literal in relative and reg <= 12
                    and not any(slot in relocations for slot in touched)):
                refs.append({"instruction_va": va, "register": "r" + str(reg),
                             "literal_va": literal, "table_va": relative[literal]["table_va"]})
            pos += width
        matches = [r["table_va"] for r in tables.values()
                   if r["layout_assumption"] == "gps" and any(
                       e["field"] == "get_extension" and e["target_va"] == start
                       and e["isa"] == isa for e in r["entries"])]
        code.append({"role_assumption": role, "isa_assumption": isa, "start_va": start,
                     "size": size, "get_extension_entry_matches": matches,
                     "literal_load_clues": refs})
        if sum(len(r["literal_load_clues"]) for r in code) > MAX_REFS:
            raise ValueError("Code reference budget exceeded")
    return {"schema": "galwear-r800-gps-interface-xref-v1", "status": "STATIC_XREF_CLUES_ONLY",
            "sha256": discovery["sha256"], "table_candidates": list(tables.values()),
            "relative_data_references": [relative[k] for k in sorted(relative)],
            "code_ranges": code, "function_identity_verified": False,
            "instruction_boundaries_verified": False, "control_flow_verified": False,
            "table_identity_verified": False, "selected_abi": None,
            "runtime_verified": False, "safe_to_flash": False}


def parse_range(value):
    try:
        role, isa, start, size = value.split(":")
        return role, isa, int(start, 0), int(size, 0)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("Expected ROLE:ISA:VA:SIZE") from exc


def main():
    from r800_android_userspace_preflight import read_regular
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--library", required=True, type=Path)
    parser.add_argument("--range", action="append", type=parse_range, default=[])
    args = parser.parse_args()
    try:
        report = audit(read_regular(args.library, LIMIT), args.range)
    except (OSError, ValueError, struct.error) as exc:
        report = {"status": "REVIEW_REQUIRED", "error": str(exc), "safe_to_flash": False}
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["status"] == "STATIC_XREF_CLUES_ONLY" else 2


if __name__ == "__main__":
    raise SystemExit(main())
