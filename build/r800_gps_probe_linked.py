#!/usr/bin/env python3
"""Probe-specific ARM32 linked geometry and import contract; no execution."""
import argparse
import hashlib
import json
from pathlib import Path
import struct

IMPORTS = frozenset("__libc_start_main dlclose dlopen dlsym fflush gnu_get_libc_version pthread_create pthread_join puts strcmp".split())
LIBS = {"libc.so.6", "libdl.so.2", "libpthread.so.0"}
LIMIT = 4 * 1024**2


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def check(raw):
    require(52 <= len(raw) <= LIMIT and raw[:7] == b"\x7fELF\x01\x01\x01", "Expected bounded ARM ELF32")
    typ, machine, version, entry, phoff, _, flags, ehsize, phsize, phnum = struct.unpack_from("<HHIIIIIHHH", raw, 16)
    require((typ, machine, version, ehsize, phsize) == (2, 40, 1, 52, 32) and flags & 0xff000400 == 0x05000000, "Expected ARM EABI5 ET_EXEC without hard-float")
    require(52 <= phoff and 1 <= phnum <= 64 and phoff + phnum * 32 <= len(raw), "Invalid program header table")
    headers = [struct.unpack_from("<8I", raw, phoff + i*32) for i in range(phnum)]
    loads = [h for h in headers if h[0] == 1 and h[5]]
    for h in loads:
        _, off, va, _, fs, ms, perm, align = h
        require(fs <= ms and off + fs <= len(raw) and va + ms <= 2**32 and perm in (4, 5, 6), "Invalid PT_LOAD geometry or permissions")
        require(align in (0, 1) or not align & (align-1) and va % align == off % align, "Invalid PT_LOAD alignment")
        require(not any(other is not h and va < other[2]+other[5] and other[2] < va+ms for other in loads), "Overlapping PT_LOAD")

    def one(kind):
        matches = [h for h in headers if h[0] == kind]
        require(len(matches) == 1, "Missing or duplicate program header: " + hex(kind))
        return matches[0]

    def mapped(va, size, perm):
        hits = [h for h in loads if h[2] <= va and va+size <= h[2]+h[4]]
        require(size > 0 and len(hits) == 1 and hits[0][6] == perm, "Unexpected file-backed segment mapping")
        return hits[0][1] + va - hits[0][2]

    require(entry % 4 == 0 and entry != 0, "Invalid ARM entry point")
    mapped(entry, 4, 5)
    tls = one(7)
    require(tls[4:8] == (4, 4, 4, 4) and tls[2] % 4 == 0 and mapped(tls[2], 4, 6) == tls[1], "Unexpected PT_TLS geometry")
    require(raw[tls[1]:tls[1]+4] == b"\x11\0\0\0", "Unexpected TLS initializer")
    interp = one(3)
    require(mapped(interp[2], interp[4], 4) == interp[1] and raw[interp[1]:interp[1]+interp[4]] == b"/lib/ld-linux.so.3\0", "Unexpected PT_INTERP")
    require(one(0x6474e551)[6] == 6, "Stack must be RW and non-executable")
    dyn = one(2)
    require(dyn[4] % 8 == 0 and 8 <= dyn[4] <= 4096 and mapped(dyn[2], dyn[4], 6) == dyn[1], "Invalid PT_DYNAMIC")
    tags = {}
    for off in range(dyn[1], dyn[1]+dyn[4], 8):
        tag, value = struct.unpack_from("<II", raw, off)
        if tag == 0:
            break
        tags.setdefault(tag, []).append(value)
    else:
        raise ValueError("Missing DT_NULL")
    # This small local-exec probe needs only PLT REL relocations.
    require(set(tags) <= {1,2,3,4,5,6,10,11,20,21,23,24,30,0x6ffffffb,0x6ffffff0,0x6ffffffe,0x6fffffff}, "Unexpected dynamic tag")
    require(all(len(v) == 1 for k,v in tags.items() if k != 1), "Duplicate singleton dynamic tag")
    def val(tag, default=None):
        return tags.get(tag, [default])[0]
    require(val(11) == 16 and val(20) == 17 and val(2) == 8*len(IMPORTS) and (24 in tags or val(30,0)&8 or val(0x6ffffffb,0)&1), "Expected immediate binding and exact PLT REL count")
    size = val(10,0)
    require(0 < size <= 4096, "Invalid dynamic string table")
    pos = mapped(val(5,0), size, 4)
    strings = raw[pos:pos+size]
    def name(index):
        end = strings.find(b"\0", index)
        require(0 < index < len(strings) and end > index, "Invalid dynamic symbol string")
        return strings[index:end].decode("ascii")
    needed = [name(i) for i in tags.get(1, [])]
    require(len(needed) == len(LIBS) and set(needed) == LIBS, "Unexpected DT_NEEDED set")
    pos = mapped(val(4,0), 8, 4)
    buckets, count = struct.unpack_from("<II", raw, pos)
    require(1 <= buckets <= 256 and count == len(IMPORTS)+1, "Unexpected dynamic symbol count")
    mapped(val(4,0), 8+4*(buckets+count), 4)
    pos = mapped(val(6,0), count*16, 4)
    require(raw[pos:pos+16] == bytes(16), "Invalid null symbol")
    imports = []
    for i in range(1,count):
        index, value, size, info, other, section = struct.unpack_from("<IIIBBH", raw, pos+i*16)
        require((value,size,info,other,section) == (0,0,0x12,0,0), "Expected undefined global function import")
        imports.append(name(index))
    require(set(imports) == IMPORTS, "Unexpected dynamic import set")
    pos = mapped(val(23,0), val(2), 4)
    slots, symbols = set(), set()
    for i in range(len(IMPORTS)):
        target, info = struct.unpack_from("<II", raw, pos+i*8)
        require(info&255 == 22 and 1 <= info>>8 < count and target%4 == 0 and target not in slots and info>>8 not in symbols, "Unexpected or duplicate JUMP_SLOT")
        mapped(target,4,6)
        slots.add(target)
        symbols.add(info>>8)
    return {"status":"ARM32_PROBE_LINKED_STATIC_ONLY", "sha256":hashlib.sha256(raw).hexdigest(), "tls_bytes":4, "imports":sorted(imports), "jump_slots":len(slots), "runtime_verified":False, "safe_to_flash":False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    args = parser.parse_args()
    try:
        with args.binary.open("rb") as stream:
            report = check(stream.read(LIMIT+1))
    except (OSError, ValueError, struct.error) as exc:
        report = {"status":"REVIEW_REQUIRED", "problems":[str(exc)], "safe_to_flash":False}
    print(json.dumps(report, sort_keys=True))
    return 0 if report["status"] == "ARM32_PROBE_LINKED_STATIC_ONLY" else 2


if __name__ == "__main__":
    raise SystemExit(main())
