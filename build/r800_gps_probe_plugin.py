#!/usr/bin/env python3
"""Strict static contract for the synthetic ARM32 dlopen plugin."""
import argparse
import hashlib
import json
from pathlib import Path
import struct

LIMIT = 1024**2


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def check(raw):
    require(52 <= len(raw) <= LIMIT and raw[:7] == b"\x7fELF\x01\x01\x01", "Expected ARM ELF32")
    typ, machine, version, entry, phoff, _, flags, ehsize, phsize, phnum = struct.unpack_from("<HHIIIIIHHH", raw, 16)
    require((typ, machine, version, entry, ehsize, phsize) == (3, 40, 1, 0, 52, 32) and flags & 0xff000400 == 0x05000000, "Expected ARM EABI5 ET_DYN with no entry")
    require(52 <= phoff and 1 <= phnum <= 64 and phoff+phnum*32 <= len(raw), "Invalid program headers")
    headers = [struct.unpack_from("<8I", raw, phoff+i*32) for i in range(phnum)]
    require(all(h[0] in (0, 1, 2, 6, 0x6474e551, 0x6474e552, 0x70000001) for h in headers), "Unexpected plugin segment")
    loads = [h for h in headers if h[0] == 1]
    for h in loads:
        _, off, va, _, fs, ms, perm, align = h
        require(0 < ms and fs <= ms and off+fs <= len(raw) and va+ms <= 2**32 and perm in (4,5,6), "Invalid plugin load")
        require(align in (0,1) or not align & (align-1) and va % align == off % align, "Invalid load alignment")
        require(not any(o is not h and va < o[2]+o[5] and o[2] < va+ms for o in loads), "Overlapping plugin loads")
    def one(kind):
        matches = [h for h in headers if h[0] == kind]
        require(len(matches) == 1, "Missing or duplicate segment")
        return matches[0]
    def mapped(va, size, perm):
        hits = [h for h in loads if h[2] <= va and va+size <= h[2]+h[4]]
        require(size > 0 and len(hits) == 1 and hits[0][6] == perm, "Invalid plugin mapping")
        return hits[0][1]+va-hits[0][2]
    require(one(0x6474e551)[6] == 6, "Executable or invalid stack")
    dyn = one(2)
    require(dyn[4] == dyn[5] and 48 <= dyn[4] <= 4096 and dyn[4]%8 == 0 and mapped(dyn[2], dyn[4], 6) == dyn[1], "Invalid dynamic segment")
    tags = {}
    for off in range(dyn[1], dyn[1]+dyn[4], 8):
        tag, value = struct.unpack_from("<II", raw, off)
        if tag == 0:
            require(not any(raw[off:dyn[1]+dyn[4]]), "Nonzero dynamic tail")
            break
        require(tag in (4,5,6,10,11) and tag not in tags, "Unexpected or duplicate dynamic tag")
        tags[tag] = value
    else:
        raise ValueError("Missing DT_NULL")
    require(set(tags) == {4,5,6,10,11} and tags[11] == 16 and tags[10] == 11, "Unexpected dynamic inventory")
    off = mapped(tags[5], 11, 4)
    require(raw[off:off+11] == b"\0probe_add\0", "Unexpected export name")
    off = mapped(tags[6], 32, 4)
    require(raw[off:off+16] == bytes(16), "Invalid null symbol")
    name, value, size, info, other, section = struct.unpack_from("<IIIBBH", raw, off+16)
    require(name == 1 and value%4 == 0 and size == 8 and info == 0x12 and other == 0 and 0 < section < 0xff00, "Unexpected function export")
    off = mapped(value, size, 5)
    require(raw[off:off+8] == bytes.fromhex("150080e21eff2fe1"), "Unexpected probe_add instructions")
    off = mapped(tags[4], 8, 4)
    buckets, count = struct.unpack_from("<II", raw, off)
    require(1 <= buckets <= 256 and count == 2, "Unexpected SYSV hash size")
    off = mapped(tags[4], 8+4*(buckets+count), 4)
    words = struct.unpack_from("<"+"I"*(buckets+count), raw, off+8)
    h = 0
    for byte in b"probe_add":
        h = (h << 4)+byte
        high = h & 0xf0000000
        if high:
            h ^= high >> 24
        h &= ~high
    expected = [0]*(buckets+count)
    expected[h % buckets] = 1
    require(list(words) == expected, "Unreachable or malformed SYSV export hash")
    return {"status":"ARM32_PLUGIN_STATIC_ONLY", "sha256":hashlib.sha256(raw).hexdigest(), "exports":["probe_add"], "imports":0, "relocations":0, "runtime_verified":False, "safe_to_flash":False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("plugin", type=Path)
    args = parser.parse_args()
    try:
        with args.plugin.open("rb") as stream:
            report = check(stream.read(LIMIT+1))
    except (OSError, ValueError, struct.error) as exc:
        report = {"status":"REVIEW_REQUIRED", "problems":[str(exc)], "safe_to_flash":False}
    print(json.dumps(report, sort_keys=True))
    return 0 if report["status"] == "ARM32_PLUGIN_STATIC_ONLY" else 2


if __name__ == "__main__":
    raise SystemExit(main())
