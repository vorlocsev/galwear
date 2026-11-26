#!/usr/bin/env python3
"""Find GPS factory range from bounded ELF32 SYSV/GNU dynamic symbols."""
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


def extended_factory(raw, mapping, tags):
    """Use shared GNU hash and version validation, then check the selected range."""
    from r800_android_linker_audit import inspect

    def one(tag):
        if len(tags.get(tag, [])) != 1:
            raise ValueError("Missing or duplicate dynamic symbol tag")
        return tags[tag][0]

    if not 1 <= one(10) <= MAX_STRINGS or one(11) != 16:
        raise ValueError("Invalid dynamic symbol metadata")
    off, _ = mapping(one(5), one(10))
    if raw[off] != 0:
        raise ValueError("Invalid dynamic string table")
    result = inspect(raw)
    count = result["dynamic_symbol_count"]
    if type(count) is not int or not 1 <= count <= MAX_SYMBOLS:
        raise ValueError("Dynamic symbol count unavailable")
    if any(s["name"] == FACTORY.decode() for s in result["unsupported_symbols"]):
        raise ValueError("Unsupported factory symbol")
    candidates = [s for s in result["symbol_exports"]
                  if s["name"] == FACTORY.decode() and not s["version_hidden"]]
    if len(candidates) != 1:
        raise ValueError("Expected exactly one default-visible factory export")
    symbol = candidates[0]
    index = symbol["index"]
    if not 1 <= index < count:
        raise ValueError("Invalid factory symbol index")
    off, _ = mapping(one(6), count * 16)
    _, value, size, info, other, section = struct.unpack_from("<IIIBBH", raw, off + 16 * index)
    if 4 in tags:
        off, _ = mapping(one(4), 8)
        buckets, nchain = struct.unpack_from("<II", raw, off)
        if not 1 <= buckets <= MAX_SYMBOLS or nchain != count:
            raise ValueError("Invalid SYSV symbol dimensions")
        off, _ = mapping(one(4), 8 + 4 * (buckets + count))
        indices = struct.unpack_from(f"<{buckets + count}I", raw, off + 8)
        head = indices[elf_hash(FACTORY) % buckets]
        seen = set()
        while head and head != index:
            if not 0 < head < count or head in seen:
                raise ValueError("Invalid SYSV lookup chain")
            seen.add(head)
            head = indices[buckets + head]
        if head != index:
            raise ValueError("Factory absent from SYSV lookup chain")
    if 0x6ffffef5 in tags:
        addr = one(0x6ffffef5)
        off, _ = mapping(addr, 16)
        buckets, first, bloom_size, shift = struct.unpack_from("<IIII", raw, off)
        if (not 1 <= buckets <= MAX_SYMBOLS or not 1 <= first <= index < count
                or not 1 <= bloom_size <= MAX_SYMBOLS or bloom_size & (bloom_size - 1)
                or shift >= 32):
            raise ValueError("Factory outside valid GNU hashed symbol range")
        h = 5381
        for byte in FACTORY:
            h = (h * 33 + byte) & 0xffffffff
        off, _ = mapping(addr + 16 + 4 * (bloom_size + h % buckets), 4)
        head, = struct.unpack_from("<I", raw, off)
        if not first <= head <= index:
            raise ValueError("Factory absent from GNU lookup chain")
        chain = addr + 16 + 4 * (bloom_size + buckets)
        for i in range(head, index + 1):
            off, _ = mapping(chain + 4 * (i - first), 4)
            word, = struct.unpack_from("<I", raw, off)
            if i == index and word & ~1 != h & ~1:
                raise ValueError("Factory GNU hash mismatch")
            if i < index and word & 1:
                raise ValueError("Factory beyond GNU bucket end")
    version = symbol["version"]
    if 0x6ffffff0 in tags:
        off, _ = mapping(one(0x6ffffff0), count * 2)
        versym, = struct.unpack_from("<H", raw, off + 2 * index)
        if versym & 0x8000 or versym == 0:
            raise ValueError("Factory version not default-visible")
        if versym >= 2:
            defs = [v for v in result["version_definitions"] if v["index"] == versym]
            if len(defs) != 1 or defs[0]["base"] or defs[0]["version"] != version:
                raise ValueError("Factory version definition unavailable")
        elif version is not None:
            raise ValueError("Unexpected version name")
    elif any(t in tags for t in (0x6ffffffc, 0x6ffffffd, 0x6ffffffe, 0x6fffffff)):
        raise ValueError("Version metadata without DT_VERSYM")
    kind = ("SYSV_AND_GNU" if 4 in tags and 0x6ffffef5 in tags
            else "GNU" if 0x6ffffef5 in tags else "SYSV")
    return checked_range(mapping, index, value, size, info, other, section, kind, version)


def checked_range(mapping, index, value, size, info, other, section, kind, version):
    if info >> 4 not in (1, 2) or info & 15 != 2 or other & 3 not in (0, 3) or not 0 < section < 0xff00:
        raise ValueError("Factory must be a defined visible STT_FUNC")
    isa = "thumb" if value & 1 else "arm"
    start = value & ~1
    align = 2 if isa == "thumb" else 4
    if not start or not 0 < size <= MAX_RANGE or start % align or size % align or start + size > 2**32:
        raise ValueError("Invalid factory symbol range")
    _, flags = mapping(start, size)
    if not flags & 1 or flags & 2:
        raise ValueError("Factory range not executable and nonwritable")
    return {"symbol_index": index, "symbol_name": FACTORY.decode(), "isa": isa,
            "start_va": start, "size": size, "hash_kind": kind,
            "symbol_version": version, "default_visible_candidate": True}


def factory_range(raw):
    mapping, _, tags = parse_elf(raw, include_tags=True)

    def one(tag):
        if len(tags.get(tag, [])) != 1:
            raise ValueError("Missing or duplicate dynamic symbol tag")
        return tags[tag][0]

    if not (4 in tags or 0x6ffffef5 in tags):
        raise ValueError("Dynamic symbol hash required")
    if any(t in tags for t in (0x6ffffef5, 0x6ffffff0, 0x6ffffffc, 0x6ffffffd,
                              0x6ffffffe, 0x6fffffff)):
        return extended_factory(raw, mapping, tags)
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
    return checked_range(mapping, index, value, size, info, other, section, "SYSV", None)


def automatic_callees(raw, factory, depth):
    """Find nonpreemptible dynamic function ranges at direct call candidates."""
    from r800_gps_pic_flow import arm_call, thumb_call
    mapping, relocations, tags = parse_elf(raw, include_tags=True)
    if 4 not in tags or any(t in tags for t in (0x6ffffef5, 0x6ffffff0, 0x6ffffffc,
                                               0x6ffffffd, 0x6ffffffe, 0x6fffffff)):
        raise ValueError("Automatic callee mode requires unversioned SYSV symbols")

    def one(tag):
        if len(tags.get(tag, [])) != 1:
            raise ValueError("Missing or duplicate callee symbol tag")
        return tags[tag][0]

    off, _ = mapping(one(4), 8)
    _, count = struct.unpack_from("<II", raw, off)
    if not 1 <= count <= MAX_SYMBOLS or one(11) != 16 or not 1 <= one(10) <= MAX_STRINGS:
        raise ValueError("Invalid callee symbol inventory")
    off, _ = mapping(one(5), one(10))
    strings = raw[off:off + one(10)]
    off, _ = mapping(one(6), count * 16)
    spans = []
    for i in range(1, count):
        name, value, size, info, other, section = struct.unpack_from("<IIIBBH", raw, off + i * 16)
        if info & 15 not in (2, 10) or not 0 < section < 0xff00 or not value:
            continue
        start = value & ~1
        isa = "thumb" if value & 1 else "arm"
        align = 2 if isa == "thumb" else 4
        # Even unsupported or zero-size function entries block overlapping candidates.
        end = start + max(size, 1)
        eligible = (info & 15 == 2 and (info >> 4 == 0 or info >> 4 in (1, 2) and other & 3 in (1, 2, 3))
                    and 0 < size <= 4096 and start % align == 0 and size % align == 0 and end <= 2**32)
        row = None
        if eligible:
            stop = strings.find(b"\0", name, min(len(strings), name + 4096)) if name < len(strings) else -1
            try:
                _, flags = mapping(start, size)
            except ValueError:
                flags = 0
            if stop > name and flags & 1 and not flags & 2:
                row = {"symbol_index": i, "symbol_name": strings[name:stop].decode("utf-8", "replace"),
                       "isa": isa, "start_va": start, "size": size}
        spans.append((start, end, i, row))
    spans.sort(key=lambda s: (s[0], s[1], s[2]))
    candidates = {}
    previous_end = 0
    for j, (start, end, _, row) in enumerate(spans):
        if (row is not None and previous_end <= start
                and (j + 1 == len(spans) or spans[j + 1][0] >= end)
                and not (start < factory["start_va"] + factory["size"] and factory["start_va"] < end)):
            candidates[(start, row["isa"])] = row
        previous_end = max(previous_end, end)

    # Linear scanning is discovery only. The flow engine checks modeled reachability.
    pending = [(factory, 0)]
    selected = {}
    for function, level in pending:
        if level >= depth:
            continue
        start, size, isa = function["start_va"], function["size"], function["isa"]
        off, _ = mapping(start, size)
        pos = 0
        while pos < size:
            va = start + pos
            if isa == "arm":
                width = 4
                call = arm_call(struct.unpack_from("<I", raw, off + pos)[0], va)
            else:
                a, = struct.unpack_from("<H", raw, off + pos)
                width = 4 if a >> 11 in (29, 30, 31) else 2
                if pos + width > size:
                    break
                b = struct.unpack_from("<H", raw, off + pos + 2)[0] if width == 4 else None
                call = thumb_call(a, b, width, va)
            pos += width
            if call is None or any(slot in relocations for slot in range(va & ~3, ((va + width - 1) & ~3) + 1, 4)):
                continue
            entry = call[:2]
            if entry in candidates and entry not in selected:
                if len(selected) >= 16:
                    raise ValueError("Automatic callee range budget exceeded")
                selected[entry] = candidates[entry]
                pending.append((candidates[entry], level + 1))
    return list(selected.values())


def audit(raw, *, auto_callees=False, callee_depth=1):
    symbol = factory_range(raw)
    if type(callee_depth) is not int or not 1 <= callee_depth <= 4 or (callee_depth != 1 and not auto_callees):
        raise ValueError("Callee depth requires automatic mode and must be between 1 and 4")
    callees = automatic_callees(raw, symbol, callee_depth) if auto_callees else []
    report = xref(raw, [("factory", symbol["isa"], symbol["start_va"], symbol["size"])],
                  assume_aapcs=auto_callees, callee_ranges=[(r["isa"], r["start_va"], r["size"]) for r in callees],
                  callee_depth=callee_depth if callees else 1)
    report.update(auto_callee_mode=auto_callees, auto_callee_candidates=callees,
                  requested_callee_depth=callee_depth, callee_discovery_complete=False)
    report.update(schema="galwear-r800-gps-factory-xref-v1", factory_symbol=symbol,
                  symbol_range_from_metadata=True, function_boundaries_verified=False,
                  factory_signature_verified=False)
    return report


def main():
    from r800_android_userspace_preflight import read_regular
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--library", required=True, type=Path)
    parser.add_argument("--auto-callees", action="store_true", help="Discover bounded direct-call symbol candidates")
    parser.add_argument("--callee-depth", type=int, default=1)
    args = parser.parse_args()
    try:
        report = audit(read_regular(args.library, LIMIT), auto_callees=args.auto_callees, callee_depth=args.callee_depth)
    except (OSError, ValueError, struct.error) as exc:
        report = {"status": "REVIEW_REQUIRED", "error": str(exc),
                  "selected_abi": None, "safe_to_flash": False}
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["status"] == "STATIC_XREF_CLUES_ONLY" else 2


if __name__ == "__main__":
    raise SystemExit(main())
