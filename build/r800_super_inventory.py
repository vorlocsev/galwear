#!/usr/bin/env python3
"""Conservative raw, single-device Android 11 LP metadata inventory.

Layout: AOSP system/core 348efca472d810d3152568913da41a081893a4e3,
fs_mgr/liblp/include/liblp/metadata_format.h and utility.cpp.
No mounts, sparse conversion, slot inference, device-mapper or extraction.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct

from r800_graphics_donor_binding import checkout_sha

MAX_IMAGE = 16 * 1024**3
MAX_METADATA = 4 * 1024**2
MAX_ENTRIES = 65536
SECTOR = 512
GEOMETRY = 4096
START = 3 * GEOMETRY
FORMATS = ("<36sIIII", "<QIQI", "<36sIQ", "<QIIQ36sI")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def checksum(raw, offset):
    return hashlib.sha256(raw[:offset] + bytes(32) + raw[offset+32:]).digest()


def name(raw):
    value, _, padding = raw.partition(b"\0")
    require(not any(padding) and re.fullmatch(rb"[A-Za-z0-9_]{1,36}", value),
            "Invalid LP name")
    return value.decode("ascii")


def geometry(raw):
    magic, size, digest, limit, slots, block = struct.unpack_from("<II32sIII", raw)
    require(magic == 0x616c4467 and size == 52, "Invalid LP geometry")
    require(checksum(raw[:size], 8) == digest, "LP geometry checksum mismatch")
    require(512 <= limit <= MAX_METADATA and limit % SECTOR == 0 and
            1 <= slots <= 4 and SECTOR <= block <= 65536 and
            block % SECTOR == 0 and block & (block-1) == 0, "Unsupported LP geometry bounds")
    return limit, slots, block


def metadata(raw, image_bytes, limit, slots, block):
    magic, major, minor, hs, digest, ts, tables_digest = struct.unpack_from("<IHHI32sI32s", raw)
    require(magic == 0x414c5030 and major == 10 and minor in (0, 1, 2) and
            hs == (256 if minor == 2 else 128), "Unsupported LP header")
    require(hs + ts <= limit, "LP tables exceed metadata slot")
    header, tables = raw[:hs], raw[hs:hs+ts]
    require(checksum(header, 12) == digest, "LP header checksum mismatch")
    require(hashlib.sha256(tables).digest() == tables_digest, "LP tables checksum mismatch")
    flags = struct.unpack_from("<I", header, 128)[0] if minor == 2 else 0
    require(flags & ~1 == 0 and (minor != 2 or not any(header[132:])), "Unsupported LP header flags")
    spans, rows = [], []
    for i, fmt in enumerate(FORMATS):
        offset, count, size = struct.unpack_from("<III", header, 80+12*i)
        require(size == struct.calcsize(fmt) and count <= MAX_ENTRIES and
                offset + count*size <= ts, "Invalid LP table descriptor")
        if count:
            spans.append((offset, offset+count*size))
        rows.append([struct.unpack_from(fmt, tables, offset+j*size) for j in range(count)])
    cursor = 0
    for start, end in sorted(spans):
        require(start == cursor, "Overlapping or noncontiguous LP tables")
        cursor = end
    require(cursor == ts, "Unreferenced LP table bytes")
    parts, extents, groups, devices = rows
    require(len(devices) == 1, "Only single-device super images supported")
    first, alignment, align_offset, size, devname, devflags = devices[0]
    require(name(devname) == "super" and devflags == 0, "Unsupported physical super device")
    require(size == image_bytes and first*SECTOR >= START+2*slots*limit and
            first*SECTOR < size and first*SECTOR % block == 0, "Invalid physical device bounds")
    require(alignment == 0 or alignment % SECTOR == 0, "Invalid physical alignment")
    require(align_offset % SECTOR == 0, "Invalid alignment offset")
    group_names, group_sizes = [], []
    for rawname, gf, maximum in groups:
        n = name(rawname)
        require(n not in group_names and gf == 0, "Duplicate or unsupported LP group")
        group_names.append(n)
        group_sizes.append(maximum)
    require("default" in group_names, "Missing default LP group")
    require(group_sizes[group_names.index("default")] == 0, "Invalid default LP group")
    used, ranges, partitions, usage = set(), [], {}, [0]*len(groups)
    for rawname, attrs, index, count, group in parts:
        n = name(rawname)
        require(n not in partitions and group < len(groups) and
                attrs & ~(1 if minor == 0 else 13) == 0 and
                index + count <= len(extents), "Invalid or unsupported LP partition")
        # Empty inactive slots are represented without extents.
        logical = 0
        entries = []
        for j in range(index, index+count):
            require(j not in used, "Shared LP extent index")
            used.add(j)
            sectors, target, sector, source = extents[j]
            length = sectors*SECTOR
            require(length > 0 and length % block == 0, "Invalid LP extent length")
            if target == 0:
                offset = sector*SECTOR
                require(source == 0 and sector >= first and offset % block == 0 and
                        offset+length <= size, "LP linear extent outside data area")
                ranges.append((offset, offset+length))
            elif target == 1:
                require(sector == source == 0, "Invalid LP zero extent")
                offset = None
            else:
                raise ValueError("Unsupported LP extent target")
            logical += length
            require(logical <= MAX_IMAGE, "LP logical size budget exceeded")
            entries.append({"type": "linear" if target == 0 else "zero",
                            "offset": offset, "bytes": length})
        usage[group] += logical
        partitions[n] = {"bytes": logical, "attributes": attrs, "group": group_names[group],
                         "extents": entries, "disabled": bool(attrs & 8)}
    require(len(used) == len(extents), "Unowned LP extents")
    last = first*SECTOR
    for start, end in sorted(ranges):
        require(start >= last, "Overlapping physical LP extents")
        last = end
    require(all(not maximum or usage[i] <= maximum for i, maximum in enumerate(group_sizes)),
            "LP group size exceeded")
    return {"version": [major, minor], "header_flags": flags, "partitions": partitions,
            "metadata_sha256": hashlib.sha256(header+tables).hexdigest()}


def inventory(image, expected, slot, source_sha):
    require(re.fullmatch(r"[0-9a-f]{64}", expected), "Expected image SHA-256")
    require(type(slot) is int and slot >= 0, "Explicit nonnegative metadata slot required")
    checkout_sha(source_sha)
    image = Path(image)
    fd = os.open(image, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        initial = os.fstat(fd)
        require(stat.S_ISREG(initial.st_mode) and START < initial.st_size <= MAX_IMAGE,
                "Expected bounded raw super file")
        def read(offset, length):
            raw = os.pread(fd, length, offset)
            require(len(raw) == length, "Truncated super input")
            return raw
        def digest():
            h = hashlib.sha256()
            for offset in range(0, initial.st_size, 1024*1024):
                h.update(read(offset, min(1024*1024, initial.st_size-offset)))
            return h.hexdigest()
        require(digest() == expected, "Super SHA-256 mismatch")
        require(read(0, 4) != b"\x3a\xff\x26\xed", "Sparse super requires separate conversion")
        primary = geometry(read(GEOMETRY, GEOMETRY))
        backup = geometry(read(2*GEOMETRY, GEOMETRY))
        require(primary == backup, "LP geometry copies disagree")
        limit, slots, block = primary
        require(slot < slots and START+2*slots*limit <= initial.st_size, "LP slot outside image")
        a = metadata(read(START+slot*limit, limit), initial.st_size, *primary)
        b = metadata(read(START+(slots+slot)*limit, limit), initial.st_size, *primary)
        require(a == b, "LP selected metadata copies disagree")
        require(digest() == expected, "Super input changed during audit")
        final = os.fstat(fd)
        require((initial.st_dev, initial.st_ino, initial.st_size, initial.st_mtime_ns, initial.st_ctime_ns) ==
                (final.st_dev, final.st_ino, final.st_size, final.st_mtime_ns, final.st_ctime_ns),
                "Super file identity changed")
    finally:
        os.close(fd)
    checkout_sha(source_sha)
    return {"schema": "galwear-r800-raw-super-inventory-v1",
            "status": "RAW_SUPER_SELECTED_SLOT_METADATA_ONLY", "source_sha": source_sha,
            "image_sha256": expected, "image_bytes": initial.st_size, "metadata_slot": slot,
            "slot_count": slots, "logical_block_bytes": block, "metadata_max_bytes": limit,
            "selected_slot_copies_match": True, **a, "all_slots_verified": False,
            "partition_contents_verified": False, "avb_verified": False,
            "hardware_tested": False, "safe_to_flash": False}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--image", type=Path, required=True)
    p.add_argument("--sha256", required=True)
    p.add_argument("--slot", type=int, required=True)
    p.add_argument("--source-sha", required=True)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    result = inventory(a.image, a.sha256, a.slot, a.source_sha)
    with a.output.open("x", encoding="utf-8") as stream:
        json.dump(result, stream, sort_keys=True, indent=2)
        stream.write("\n")
    print(result["status"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
