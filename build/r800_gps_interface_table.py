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


def parse_elf(raw, *, include_tags=False):
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

    def memory_mapping(va, size):
        # Count every intersecting memory extent, including zero-fill tails.
        # A partial overlap is ambiguous even if one segment covers the range.
        if not 0 <= va < 2**32 or not 0 < size <= 2**32 - va:
            raise ValueError("Invalid address range")
        end = va + size
        hits = [segment for segment in loads
                if segment[3] and segment[0] < end and va < segment[0] + segment[3]]
        if len(hits) != 1:
            raise ValueError("Address not uniquely mapped in load memory")
        start, off, fs, ms, pf = hits[0]
        if va < start or end > start + ms:
            raise ValueError("Address not wholly mapped in load memory")
        return start, off, fs, ms, pf

    def mapping(va, size):
        start, off, fs, _, pf = memory_mapping(va, size)
        if va + size > start + fs:
            raise ValueError("Address not uniquely file-backed")
        return off + va - start, pf

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
            try:
                memory_mapping(target, 4)
            except ValueError as exc:
                raise ValueError("Relocation outside or ambiguously mapped in load memory") from exc
            relocations[target] = (typ, sym)
    return (mapping, relocations, tags) if include_tags else (mapping, relocations)


def symbolic_code_targets(raw, mapping, relocations, tags, *, objects=False):
    """Conservative zero-addend REL references; never apply relocations."""
    wanted = {slot: (typ, sym) for slot, (typ, sym) in relocations.items()
              if typ in ((2, 21) if objects else (2, 21, 22)) and sym}
    if not wanted:
        return {}
    # This optional mode deliberately excludes versioned and GNU-only symbol
    # inventories until their local binding rules are independently reviewed.
    if 4 not in tags or any(t in tags for t in (0x6ffffef5, 0x6ffffff0,
                                               0x6ffffffc, 0x6ffffffd,
                                               0x6ffffffe, 0x6fffffff)):
        raise ValueError("Symbolic mode requires unversioned SYSV symbols")

    def one(tag):
        if len(tags.get(tag, [])) != 1:
            raise ValueError("Missing or duplicate symbol tag")
        return tags[tag][0]

    if one(11) != 16:
        raise ValueError("Invalid DT_SYMENT")
    addr = one(4)
    off, _ = mapping(addr, 8)
    buckets, count = struct.unpack_from("<II", raw, off)
    if not 1 <= buckets <= 262144 or not 1 <= count <= 262144:
        raise ValueError("Invalid SYSV symbol dimensions")
    off, _ = mapping(addr, 8 + 4 * (buckets + count))
    indices = struct.unpack_from(f"<{buckets + count}I", raw, off + 8)
    if any(i >= count for i in indices) or indices[buckets] != 0:
        raise ValueError("Invalid SYSV hash indices")
    done = {0}
    for head in indices[:buckets]:
        seen = set()
        while head not in done:
            if head in seen:
                raise ValueError("Cyclic SYSV hash chain")
            seen.add(head)
            head = indices[buckets + head]
        done.update(seen)
    symoff, _ = mapping(one(6), count * 16)
    strsize = one(10)
    if not 1 <= strsize <= 8 * 1024**2:
        raise ValueError("Invalid dynamic string size")
    stroff, _ = mapping(one(5), strsize)
    strings = raw[stroff:stroff + strsize]
    if strings[0] != 0:
        raise ValueError("Invalid dynamic string table")
    targets = {}
    for slot, (typ, sym) in wanted.items():
        if sym >= count:
            raise ValueError("Relocation symbol index out of bounds")
        name, value, size, info, other, section = struct.unpack_from("<IIIBBH", raw, symoff + sym * 16)
        if name >= len(strings):
            raise ValueError("Invalid relocation symbol name")
        end = strings.find(b"\0", name, min(len(strings), name + 4096))
        if end < 0:
            raise ValueError("Unterminated relocation symbol name")
        binding, visibility = info >> 4, other & 3
        if (info & 15 != (1 if objects else 2) or not 0 < section < 0xff00 or not value or not size
                or not (binding == 0 or binding in (1, 2) and visibility in (1, 2, 3))):
            continue
        try:
            off, _ = mapping(slot, 4)
            if struct.unpack_from("<I", raw, off)[0] != 0:
                continue
            start = value if objects else value & ~1
            align = 4 if objects else (2 if value & 1 else 4)
            if start % align or size % align:
                continue
            _, flags = mapping(start, size)
            if objects:
                if not flags & 4 or flags & 1:
                    continue
            elif not flags & 1 or flags & 2:
                continue
        except ValueError:
            continue
        targets[slot] = {"value": value, "symbol_index": sym,
                         "symbol_name": strings[name:end].decode("utf-8", "replace"),
                         "relocation_type": typ, "zero_addend_only": True,
                         "symbol_size": size}
    return targets


def inspect_table(raw, address, layout, mapping, relocations, digest, symbolic_targets=None):
    if layout not in LAYOUTS or type(address) is not int or not 0 <= address <= 0xffffffff or address % 4:
        raise ValueError("Invalid table address or layout")
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
        symbolic = (symbolic_targets or {}).get(slot)
        pointer = symbolic["value"] if symbolic is not None else value
        if (relocation == (23, 0) or symbolic is not None) and pointer:
            target, isa = pointer & ~1, "thumb" if pointer & 1 else "arm"
            try:
                _, target_flags = mapping(target, 2 if isa == "thumb" else 4)
                if target % (2 if isa == "thumb" else 4) == 0 and target_flags & 1 and not target_flags & 2:
                    row.update(target_va=target, isa=isa, status=(
                        "SYMBOLIC_EXECUTABLE_CANDIDATE" if symbolic is not None
                        else "RELATIVE_EXECUTABLE_CANDIDATE"))
                    if symbolic is not None:
                        row["symbolic_evidence"] = symbolic
            except ValueError:
                pass
        elif relocation is None and value == 0:
            row["status"] = "NULL_WORD"
        entries.append(row)
    return {"schema": "galwear-r800-gps-interface-table-v1", "status": "STATIC_TABLE_CLUES_ONLY",
            "sha256": digest, "layout_assumption": layout,
            "table_va": address, "declared_size": declared, "entries": entries,
            "table_identity_verified": False, "relocations_applied": False,
            "instruction_targets_verified": False, "callback_layout_verified": False,
            "selected_abi": None, "runtime_verified": False, "safe_to_flash": False}


MAX_CANDIDATES = 256


def audit(raw, address, layout, *, symbolic=False):
    mapping, relocations, tags = parse_elf(raw, include_tags=True)
    targets = symbolic_code_targets(raw, mapping, relocations, tags) if symbolic else {}
    return inspect_table(raw, address, layout, mapping, relocations,
                         hashlib.sha256(raw).hexdigest(), targets)


def discover(raw, *, symbolic=False):
    """Strict heuristic: exact size and a supported code pointer in every slot."""
    mapping, relocations, tags = parse_elf(raw, include_tags=True)
    targets = symbolic_code_targets(raw, mapping, relocations, tags) if symbolic else {}
    digest = hashlib.sha256(raw).hexdigest()
    candidates = []
    relative = {slot for slot, reloc in relocations.items() if reloc == (23, 0)}
    eligible = relative | set(targets)
    for slot in sorted(eligible):
        address = slot - 4
        if address < 0 or address in relocations:
            continue
        try:
            off, flags = mapping(address, 4)
        except ValueError:
            continue
        if not flags & 4 or flags & 1:
            continue
        declared, = struct.unpack_from("<I", raw, off)
        for layout, fields in LAYOUTS.items():
            if declared != 4 * (1 + len(fields)):
                continue
            if not all(address + 4 * i in eligible for i in range(1, len(fields) + 1)):
                continue
            try:
                row = inspect_table(raw, address, layout, mapping, relocations, digest, targets)
            except ValueError:
                continue
            if not all(e["status"] in ("RELATIVE_EXECUTABLE_CANDIDATE", "SYMBOLIC_EXECUTABLE_CANDIDATE") for e in row["entries"]):
                continue
            if len(candidates) >= MAX_CANDIDATES:
                raise ValueError("Interface candidate budget exceeded")
            candidates.append(row)
    return {"schema": "galwear-r800-gps-interface-discovery-v1",
            "status": "STATIC_CANDIDATES_ONLY", "sha256": digest,
            "candidate_count": len(candidates), "candidates": candidates,
            "relative_slots_examined": len(relative),
            "exact_size_all_relative_code_pointers_only": not symbolic,
            "symbolic_mode": symbolic, "symbolic_slots_resolved": len(targets),
            "discovery_complete": False, "table_identity_verified": False,
            "selected_abi": None, "runtime_verified": False, "safe_to_flash": False}


def main():
    from r800_android_userspace_preflight import read_regular
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--library", type=Path, required=True)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--table-va", type=lambda s: int(s, 0))
    mode.add_argument("--discover", action="store_true")
    parser.add_argument("--layout", choices=LAYOUTS)
    parser.add_argument("--symbolic", action="store_true", help="Opt in to conservative zero-addend symbol clues")
    args = parser.parse_args()
    if args.discover == (args.layout is not None):
        parser.error("--layout is required only with --table-va")
    try:
        raw = read_regular(args.library, LIMIT)
        report = (discover(raw, symbolic=args.symbolic) if args.discover
                  else audit(raw, args.table_va, args.layout, symbolic=args.symbolic))
    except (OSError, ValueError, struct.error) as exc:
        report = {"status": "REVIEW_REQUIRED", "error": str(exc), "safe_to_flash": False}
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["status"] in ("STATIC_TABLE_CLUES_ONLY", "STATIC_CANDIDATES_ONLY") else 2


if __name__ == "__main__":
    raise SystemExit(main())
