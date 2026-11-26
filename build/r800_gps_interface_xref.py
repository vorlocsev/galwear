#!/usr/bin/env python3
"""Bounded ELF32 GPS table references; no inferred function identity."""
import argparse
import json
from pathlib import Path
import struct

from r800_gps_interface_table import discover, parse_elf, symbolic_code_targets, LIMIT

from r800_gps_pic_flow import audit as pic_flow, audit_thumb as thumb_flow, leaf_analyzer, code_spans, thumb_literal

MAX_RANGE = 65536
MAX_REFS = 4096
ROLES = ("factory", "get_extension")


def arm_pic_clues(raw, off, start, size, relocations, tables, direct):
    """Adjacent unconditional MOVW/MOVT/ADD-PC patterns, not CFG evidence."""
    clues = []
    for pos in range(0, size - 11, 4):
        va = start + pos
        if any(va + i in relocations for i in (0, 4, 8)):
            continue
        lo, hi, add = struct.unpack_from("<III", raw, off + pos)
        reg = (lo >> 12) & 15
        if (lo & 0xfff00000 != 0xe3000000 or hi & 0xfff00000 != 0xe3400000
                or reg > 12 or (hi >> 12) & 15 != reg
                or add & 0xfff00ff0 != 0xe0800000):
            continue
        rn, rd, rm = (add >> 16) & 15, (add >> 12) & 15, add & 15
        if rd > 12 or (rn, rm) not in ((15, reg), (reg, 15)):
            continue
        def imm16(word):
            return ((word >> 4) & 0xf000) | (word & 0xfff)
        delta = imm16(lo) | (imm16(hi) << 16)
        if delta & 0x80000000:
            delta -= 1 << 32
        # A32 reads PC as the ADD address plus eight bytes.
        address = va + 16 + delta
        if not 0 <= address <= 0xffffffff:
            continue
        base = {"movw_va": va, "movt_va": va + 4, "add_va": va + 8,
                "computed_va": address, "register": "r" + str(rd)}
        if address in tables:
            clues.append({**base, "table_va": address,
                          "reference_kind": "ARM_PIC_TABLE_ADDRESS_CANDIDATE"})
        if pos + 16 > size or va + 12 in relocations:
            continue
        load, = struct.unpack_from("<I", raw, off + pos + 12)
        dest = (load >> 12) & 15
        if (load & 0xff700000 != 0xe5100000 or (load >> 16) & 15 != rd
                or dest > 12):
            continue
        delta = load & 0xfff
        slot = address + (delta if load & (1 << 23) else -delta)
        if slot not in direct:
            continue
        clues.append({**base, "dereference_va": va + 12, "register": "r" + str(dest),
                      "slot_va": slot, "table_va": direct[slot]["table_va"],
                      "reference_kind": "ARM_PIC_RELOCATED_SLOT_CANDIDATE"})
    return clues


def thumb_pic_clues(raw, off, start, size, relocations, tables, direct):
    """Adjacent T32 MOVW/MOVT, T16 ADD-PC and optional T32 LDR clues."""
    clues = []
    pos = 0
    def clean(va, width):
        return not any(slot in relocations for slot in range(
            va & ~3, ((va + width - 1) & ~3) + 1, 4))
    def imm16(a, b):
        return ((a & 15) << 12) | ((a & 0x400) << 1) | ((b & 0x7000) >> 4) | (b & 255)
    while pos + 2 <= size:
        first, = struct.unpack_from("<H", raw, off + pos)
        width = 4 if first >> 11 in (0b11101, 0b11110, 0b11111) else 2
        # Do not infer unconditional execution beyond a possible IT block.
        if first & 0xff00 == 0xbf00 and first & 15:
            break
        p = pos
        pos += width
        if p + 10 > size or not clean(start + p, 10):
            continue
        a, b, c, d, add = struct.unpack_from("<5H", raw, off + p)
        reg = (b >> 8) & 15
        if (a & 0xfbf0 != 0xf240 or c & 0xfbf0 != 0xf2c0
                or b & 0x8000 or d & 0x8000 or reg > 12
                or (d >> 8) & 15 != reg
                or add != (0x4478 | (reg & 7) | ((reg & 8) << 4))):
            continue
        delta = imm16(a, b) | (imm16(c, d) << 16)
        if delta & 0x80000000:
            delta -= 1 << 32
        va = start + p
        address = va + 12 + delta
        if not 0 <= address <= 0xffffffff:
            continue
        base = {"movw_va": va, "movt_va": va + 4, "add_va": va + 8,
                "computed_va": address, "register": "r" + str(reg)}
        if address in tables:
            clues.append({**base, "table_va": address,
                          "reference_kind": "THUMB_PIC_TABLE_ADDRESS_CANDIDATE"})
        if p + 14 > size or not clean(va + 10, 4):
            continue
        a, b = struct.unpack_from("<HH", raw, off + p + 10)
        dest = b >> 12
        if dest > 12 or a & 15 != reg:
            continue
        if a & 0xfff0 == 0xf8d0:
            slot = address + (b & 0xfff)
        elif a & 0xfff0 == 0xf850 and b & 0xf00 == 0xc00:
            slot = address - (b & 255)
        else:
            continue
        if slot in direct:
            clues.append({**base, "dereference_va": va + 10, "register": "r" + str(dest),
                          "slot_va": slot, "table_va": direct[slot]["table_va"],
                          "reference_kind": "THUMB_PIC_RELOCATED_SLOT_CANDIDATE"})
    return clues


def audit(raw, ranges=(), *, symbolic=False, assume_aapcs=False, callee_ranges=(), callee_depth=1, data_by_range=None):
    discovery = discover(raw, symbolic=symbolic)
    mapping, relocations, tags = parse_elf(raw, include_tags=True)
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
    symbolic_refs = {}
    if symbolic:
        for slot, evidence in symbolic_code_targets(raw, mapping, relocations, tags, objects=True).items():
            value = evidence["value"]
            if value not in tables or evidence["symbol_size"] < tables[value]["declared_size"]:
                continue
            _, flags = mapping(slot, 4)
            if flags & 4:
                symbolic_refs[slot] = {"slot_va": slot, "table_va": value,
                                       "source_executable": bool(flags & 1),
                                       "symbolic_evidence": evidence,
                                       "got_slot_candidate": evidence["relocation_type"] == 21 and bool(flags & 2) and not flags & 1}
    direct = {**relative, **symbolic_refs}
    if len(direct) > MAX_REFS:
        raise ValueError("Table reference budget exceeded")
    # A relative literal may point to a data slot, not directly to the table.
    # Only an immediately adjacent, zero-offset dereference is recognized.
    indirect = {}
    if symbolic:
        for slot, reloc in relocations.items():
            if reloc != (23, 0):
                continue
            try:
                off, flags = mapping(slot, 4)
            except ValueError:
                continue
            value, = struct.unpack_from("<I", raw, off)
            if flags & 4 and value in symbolic_refs and symbolic_refs[value]["got_slot_candidate"]:
                indirect[slot] = value
    if len(indirect) > MAX_REFS:
        raise ValueError("Indirect reference budget exceeded")
    ranges = tuple(ranges)
    callee_ranges = tuple(callee_ranges)
    if type(callee_depth) is not int or not 1 <= callee_depth <= 4 or (callee_depth != 1 and not callee_ranges):
        raise ValueError("Callee depth requires explicit ranges and must be between 1 and 4")
    if callee_ranges and (not assume_aapcs or len(callee_ranges) > 16):
        raise ValueError("Explicit callee ranges require AAPCS mode; maximum 16")
    data_by_range = data_by_range or {}
    leaves = {}
    spans = [(start, start + size) for _, _, start, size in ranges]
    for isa, start, size in callee_ranges:
        align = 4 if isa == "arm" else 2
        if (isa not in ("arm", "thumb") or type(start) is not int or type(size) is not int
                or not 0 <= start < 2**32 or not 0 < size <= 4096
                or start % align or size % align or start + size > 2**32
                or any(start < b and a < start + size for a, b in spans)):
            raise ValueError("Invalid or overlapping callee range")
        _, flags = mapping(start, size)
        if not flags & 1 or flags & 2:
            raise ValueError("Callee range not executable and nonwritable")
        leaves[(start, isa)] = size
        spans.append((start, start + size))
    leaf = leaf_analyzer(raw, mapping, relocations, tables, direct, leaves, max_depth=callee_depth, data_by_range=data_by_range) if leaves else None
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
        data_ranges = data_by_range.get((start, isa), ())
        islands = code_spans(start, size, isa, data_ranges)
        refs = []
        for lo, hi in islands:
            pos = lo - start
            while pos < hi - start:
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
                    if pos + width > hi - start:
                        raise ValueError("Truncated Thumb instruction candidate")
                    tail = struct.unpack_from("<H", raw, off + pos + 2)[0] if width == 4 else None
                    decoded = thumb_literal(word, tail, width, va)
                    if decoded is not None:
                        reg, literal = decoded
                touched = range(va & ~3, ((va + width - 1) & ~3) + 1, 4)
                if (literal in direct and reg <= 12
                        and not any(slot in relocations for slot in touched)):
                    refs.append({"instruction_va": va, "register": "r" + str(reg),
                                 "literal_va": literal, "table_va": direct[literal]["table_va"]})
                    if literal in symbolic_refs:
                        refs[-1]["reference_kind"] = "SYMBOLIC_OBJECT"
                if (literal in indirect and reg <= 12 and pos + width + align <= hi - start
                        and not any(slot in relocations for slot in touched)):
                    next_va = va + width
                    next_touched = range(next_va & ~3, ((next_va + align - 1) & ~3) + 1, 4)
                    dest = None
                    if isa == "arm":
                        op, = struct.unpack_from("<I", raw, off + pos + width)
                        if op & 0xfff00fff == 0xe5900000 and (op >> 16) & 15 == reg:
                            dest = (op >> 12) & 15
                    else:
                        op, = struct.unpack_from("<H", raw, off + pos + width)
                        if op & 0xffc0 == 0x6800 and (op >> 3) & 7 == reg:
                            dest = op & 7
                    if dest is not None and dest <= 12 and not any(slot in relocations for slot in next_touched):
                        got = indirect[literal]
                        refs.append({"instruction_va": va, "dereference_va": next_va,
                                     "register": "r" + str(dest), "literal_va": literal,
                                     "got_slot_va": got, "table_va": symbolic_refs[got]["table_va"],
                                     "reference_kind": "ADJACENT_GOT_DEREFERENCE_CANDIDATE"})
                pos += width
        matches = [r["table_va"] for r in tables.values()
                   if r["layout_assumption"] == "gps" and any(
                       e["field"] == "get_extension" and e["target_va"] == start
                       and e["isa"] == isa for e in r["entries"])]
        code.append({"role_assumption": role, "isa_assumption": isa, "start_va": start,
                     "size": size, "get_extension_entry_matches": matches,
                     "literal_load_clues": refs,
                     "pic_flow": pic_flow(raw, off, start, size, relocations, tables, direct, assume_aapcs=assume_aapcs, mapping=mapping, leaf=leaf, data_ranges=data_ranges)
                     if isa == "arm" else thumb_flow(raw, off, start, size, relocations, tables, direct, assume_aapcs=assume_aapcs, mapping=mapping, leaf=leaf, data_ranges=data_ranges),
                     "data_ranges": data_ranges,
                     "pic_clues": [clue for lo, hi in islands for clue in
                                   (arm_pic_clues if isa == "arm" else thumb_pic_clues)(
                                       raw, off + lo - start, lo, hi - lo, relocations, tables, direct)]})
        if sum(len(r["literal_load_clues"]) + len(r["pic_clues"])
               + len((r["pic_flow"] or {}).get("events", [])) + len((r["pic_flow"] or {}).get("assumed_calls", [])) for r in code) > MAX_REFS:
            raise ValueError("Code reference budget exceeded")
    return {"schema": "galwear-r800-gps-interface-xref-v1", "status": "STATIC_XREF_CLUES_ONLY",
            "sha256": discovery["sha256"], "table_candidates": list(tables.values()),
            "relative_data_references": [relative[k] for k in sorted(relative)],
            "symbolic_data_references": [symbolic_refs[k] for k in sorted(symbolic_refs)],
            "symbolic_mode": symbolic, "got_membership_verified": False,
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


def parse_callee(value):
    try:
        isa, start, size = value.split(":")
        return isa, int(start, 0), int(size, 0)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("Expected ISA:VA:SIZE") from exc


def main():
    from r800_android_userspace_preflight import read_regular
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--library", required=True, type=Path)
    parser.add_argument("--range", action="append", type=parse_range, default=[])
    parser.add_argument("--symbolic", action="store_true")
    parser.add_argument("--assume-aapcs", action="store_true", help="Opt in to opaque direct call summaries")
    parser.add_argument("--callee", action="append", type=parse_callee, default=[])
    parser.add_argument("--callee-depth", type=int, default=1, help="Maximum explicit call depth (1-4)")
    args = parser.parse_args()
    try:
        report = audit(read_regular(args.library, LIMIT), args.range, symbolic=args.symbolic, assume_aapcs=args.assume_aapcs, callee_ranges=args.callee, callee_depth=args.callee_depth)
    except (OSError, ValueError, struct.error) as exc:
        report = {"status": "REVIEW_REQUIRED", "error": str(exc), "safe_to_flash": False}
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["status"] == "STATIC_XREF_CLUES_ONLY" else 2


if __name__ == "__main__":
    raise SystemExit(main())
