"""Read-only evidence for the AOSP hiddenapi DEX map relocation pattern.

Compare the stored SHA-1 against a virtual pre-encoding layout. Never emit
a reconstructed DEX, modify a file, or approve execution or hidden API policy.
Strict dex_inventory remains unchanged.
Reference: AOSP art ed0e3cd7d33c1dc3db9b23c451aea72355a13c0d,
tools/hiddenapi/hiddenapi.cc, DexFileEditor.
"""
import hashlib
import struct
import zlib

from r800_art_inventory import MAX_DEX


def require(value, message):
    if not value:
        raise ValueError(message)


def observe(data):
    require(112 <= len(data) <= MAX_DEX and data[:8] == b"dex\n039\0",
            "Expected standard DEX 039")
    size, header, endian = struct.unpack_from("<III", data, 32)
    require((size, header, endian) == (len(data), 112, 0x12345678),
            "Invalid DEX header")
    require(zlib.adler32(data[12:]) & 0xffffffff == struct.unpack_from("<I", data, 8)[0],
            "DEX Adler-32 mismatch")
    map_off = struct.unpack_from("<I", data, 52)[0]
    data_size, data_off = struct.unpack_from("<II", data, 104)
    require(112 <= data_off <= map_off <= size-4 and map_off % 4 == 0
            and data_off + data_size == size, "Invalid map or data bounds")
    count = struct.unpack_from("<I", data, map_off)[0]
    require(3 <= count <= 4096 and map_off + 4 + 12*count == size,
            "Expected terminal map")
    entries = [struct.unpack_from("<HHII", data, map_off+4+12*i) for i in range(count)]
    require(len({e[0] for e in entries}) == count and
            all(e[1] == 0 and e[2] > 0 and e[3] < size for e in entries)
            and all(a[3] < b[3] for a,b in zip(entries,entries[1:])),
            "Invalid map entries")
    require(entries[0] == (0,0,1,0) and entries[-1] == (0x1000,0,1,map_off),
            "Unexpected map endpoints")
    typ, _, n, off = entries[-2]
    require(typ == 0xf000 and n == 1 and data_off <= off <= map_off-4 and off % 4 == 0,
            "No terminal hiddenapi class-data section")
    length = struct.unpack_from("<I", data, off)[0]
    classes = struct.unpack_from("<I", data, 96)[0]
    minimum = 4+4*classes
    require(classes > 0 and minimum <= length <= map_off-off and
            (off+length+3)&~3 == map_off and not any(data[off+length:map_off]),
            "Invalid hiddenapi section bounds")
    # Hash only a virtual layout: the old header, unchanged original body,
    # and old map without the appended metadata entry. No output bytes.
    header_bytes = bytearray(data[32:112])
    old_size = off + 4 + 12*(count-1)
    struct.pack_into("<I", header_bytes, 0, old_size)
    struct.pack_into("<I", header_bytes, 52-32, off)
    struct.pack_into("<I", header_bytes, 104-32, old_size-data_off)
    h = hashlib.sha1(header_bytes)
    h.update(memoryview(data)[112:off])
    h.update(struct.pack("<I", count-1))
    h.update(memoryview(data)[map_off+4:map_off+4+12*(count-2)])
    h.update(struct.pack("<HHII", 0x1000, 0, 1, off))
    match = h.digest() == data[12:32]
    return {"status": "PRE_HIDDENAPI_SHA1_MATCH_ONLY" if match else "REVIEW_REQUIRED",
            "hiddenapi_section_bytes": length, "class_defs": classes,
            "original_layout_bytes": old_size,
            "stored_sha1_matches_virtual_pre_encoding": match,
            "current_sha1_matches": hashlib.sha1(data[32:]).digest()==data[12:32],
            "current_adler32_matches": True, "hiddenapi_policy_verified": False,
            "bytecode_verified": False, "safe_to_flash": False}
