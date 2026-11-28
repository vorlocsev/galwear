#!/usr/bin/env python3
"""Static OAT 183 location inventory and VDEX comparison.

Layout checked against LineageOS/android_art 7f2b48980eaa3e9ebeb3fe2df55ae4beb96f8248,
runtime/oat.h, runtime/oat_file.cc, libartbase/arch/instruction_set.h.
Only file-backed ELF section metadata is inspected; no relocation or execution.
"""
import hashlib
import re
import struct

from r800_extract_super import require
from r800_art_vdex_binding import expected_checksums, inspect_vdex, MAX_FILES

MAX_OAT = 128*1024**2
MAX_KV = 1024*1024
HEADER = 60
ISAS = {"arm": (1, 40, (1, 3)), "arm64": (2, 183, (2,))}
LOCATION = re.compile(r"/(?:system|system_ext|product|vendor|odm|apex)/[A-Za-z0-9_./@-]+\.(?:jar|dex)(?:!classes(?:[2-9]|[1-9][0-9]+)\.dex)?")


def oat_section(raw, isa):
    require(isa in ISAS and 52 <= len(raw) <= MAX_OAT, "Invalid OAT size or requested ISA")
    cls, machine, _ = ISAS[isa]
    require(raw[:7] == b"\x7fELF"+bytes((cls, 1, 1)) and
            struct.unpack_from("<HH", raw, 16) == (3, machine), "OAT ELF ISA/type mismatch")
    if cls == 1:
        off = struct.unpack_from("<I", raw, 32)[0]
        eh, _, _, ent, count, names = struct.unpack_from("<6H", raw, 40)
        fmt, size = "<10I", 52
    else:
        require(len(raw) >= 64, "Truncated ELF64 header")
        off = struct.unpack_from("<Q", raw, 40)[0]
        eh, _, _, ent, count, names = struct.unpack_from("<6H", raw, 52)
        fmt, size = "<IIQQQQIIQQ", 64
    require(eh == size and ent == struct.calcsize(fmt) and 0 < names < count <= 4096
            and off >= size and off+ent*count <= len(raw), "Invalid ELF section table")
    sections = [struct.unpack_from(fmt, raw, off+i*ent) for i in range(count)]
    s = sections[names]
    require(s[1] == 3 and 0 < s[5] <= MAX_KV and s[4]+s[5] <= len(raw), "Invalid ELF name table")
    strings = raw[s[4]:s[4]+s[5]]
    candidates = []
    for sec in sections:
        n = sec[0]
        require(n < len(strings) and strings.find(b"\0", n) >= 0, "Invalid ELF section name")
        name = strings[n:strings.index(b"\0", n)]
        if name not in (b".rodata", b".oatdata"):
            continue
        start, length = sec[4:6]
        require(sec[1] == 1 and start+length <= len(raw), "Invalid OAT data section")
        if raw[start:start+4] == b"oat\n":
            candidates.append((start, length))
    require(len(candidates) == 1, "OAT data section not unique")
    return candidates[0]


def inspect_oat(raw, isa):
    start, size = oat_section(raw, isa)
    require(size >= HEADER and raw[start:start+8] == b"oat\n183\0", "Unsupported OAT 183 header")
    fields = struct.unpack_from("<13I", raw, start+8)
    checksum, instruction, features, count, dex_off, executable = fields[:6]
    kv = fields[-1]
    require(instruction in ISAS[isa][2], "OAT header ISA differs from ELF ISA")
    require(1 <= count <= MAX_FILES and kv <= MAX_KV and HEADER+kv <= dex_off < size,
            "Invalid OAT dex table or key-value bounds")
    require(executable % 4096 == 0, "Unaligned OAT executable offset")
    store = raw[start+HEADER:start+HEADER+kv]
    pairs = {}
    if store:
        require(store.endswith(b"\0"), "Unterminated OAT key-value store")
        parts = store[:-1].split(b"\0")
        require(len(parts) % 2 == 0 and len(parts) <= 512, "Invalid OAT key-value store")
        for key, value in zip(parts[::2], parts[1::2]):
            key = key.decode("ascii")
            require(key and key not in pairs, "Duplicate or empty OAT key")
            pairs[key] = value.decode("utf-8")
    cursor = dex_off
    rows = []
    for _ in range(count):
        require(cursor+4 <= size, "Truncated OAT DEX location length")
        length = struct.unpack_from("<I", raw, start+cursor)[0]
        cursor += 4
        require(0 < length <= 4096 and cursor+length+32 <= size, "Truncated OAT DEX record")
        loc = raw[start+cursor:start+cursor+length].decode("ascii")
        require(LOCATION.fullmatch(loc) and ".." not in loc.split("/"), "Unsupported OAT DEX location")
        cursor += length
        values = struct.unpack_from("<8I", raw, start+cursor)
        cursor += 32
        rows.append({"location": loc, "location_checksum": values[0], "dex_offset": values[1],
                     "class_offsets_offset": values[2], "lookup_table_offset": values[3],
                     "dex_layout_sections_offset": values[4], "bss_mapping_offsets": list(values[5:])})
    require(len({row["location"] for row in rows}) == len(rows), "Duplicate OAT DEX location")
    return {"version": "183", "isa": isa, "instruction_set": instruction, "features_bitmap": features,
            "reported_oat_checksum": checksum, "oat_checksum_verified": False,
            "executable_offset": executable, "dex_records": rows,
            "literal_bootclasspath": pairs.get("bootclasspath"),
            "literal_bootclasspath_checksums": pairs.get("bootclasspath-checksums"),
            "compiler_filter": pairs.get("compiler-filter"),
            "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw),
            "machine_code_verified": False, "record_offset_targets_verified": False}


def compare(oat_raw, vdex_raw, isa, paths, artifacts):
    oat = inspect_oat(oat_raw, isa)
    vdex = inspect_vdex(vdex_raw)
    expected = expected_checksums(paths, artifacts)
    locations = [row["path"] if row["entry"] in (row["path"], "classes.dex")
                 else row["path"]+"!"+row["entry"] for row in expected]
    checksums = [row["checksum"] for row in expected]
    observed = oat["dex_records"]
    locations_match = locations == [row["location"] for row in observed]
    checksums_match = checksums == [row["location_checksum"] for row in observed] == vdex["location_checksums"]
    return {"status": "OAT_VDEX_LITERAL_LOCATION_CHECKSUMS_MATCH_ONLY"
                      if locations_match and checksums_match else "REVIEW_REQUIRED",
            "oat": oat, "vdex": vdex, "expected": expected,
            "literal_locations_match": locations_match, "ordered_checksums_match": checksums_match,
            "oat_vdex_compatibility_verified": False, "boot_image_verified": False,
            "art_initialization_verified": False, "hardware_tested": False, "safe_to_flash": False}
