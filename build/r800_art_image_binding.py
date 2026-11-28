#!/usr/bin/env python3
"""Static Android 11 ART image 085 header and OAT checksum comparison.

Layout: LineageOS/android_art 7f2b48980eaa3e9ebeb3fe2df55ae4beb96f8248,
runtime/image.h, runtime/image.cc and runtime/gc/space/image_space.cc.
Compressed blocks are inventoried, never decompressed or mapped.
"""
import hashlib
import struct

from r800_extract_super import require
from r800_art_oat_binding import compare as compare_oat

HEADER = 256
PAGE = 4096
MAX_IMAGE = 128*1024**2
MAX_EXPANDED = 512*1024**2
SECTION_NAMES = ("objects", "art_fields", "art_methods", "runtime_methods",
                 "im_tables", "imt_conflict_tables", "dex_cache_arrays",
                 "interned_strings", "class_table", "string_reference_offsets",
                 "metadata", "bitmap")


def inspect_image(raw, isa):
    require(isa in ("arm", "arm64") and HEADER <= len(raw) <= MAX_IMAGE,
            "Invalid ART image size or ISA")
    require(raw[:8] == b"art\n085\0", "Unsupported ART 085 header")
    (reservation, components, begin, size, checksum, oat_checksum,
     oat_begin, oat_data, oat_data_end, oat_end, boot_begin, boot_size,
     boot_components, boot_checksum, roots, pointer) = struct.unpack_from("<16I", raw, 8)
    require(pointer == (4 if isa == "arm" else 8), "ART pointer size differs from ISA")
    require(reservation % PAGE == 0 and components <= 128 and
            ((components == 0) == (reservation == 0)), "Invalid ART reservation or component count")
    require(0 < begin and begin % PAGE == 0 and HEADER <= size <= MAX_EXPANDED
            and begin+size < 2**32, "Invalid ART image address range")
    require(0 < oat_begin < oat_data <= oat_data_end <= oat_end, "Invalid ART OAT address range")
    require(begin+size <= oat_begin, "ART image overlaps OAT range")
    require(not reservation or reservation >= size, "ART reservation too small")
    require(begin <= roots < begin+size, "ART roots outside image")
    require((boot_components == 0 and boot_begin == boot_size == boot_checksum == 0)
            or (0 < boot_components <= 128 and boot_begin > 0 and boot_size > 0
                and boot_begin+boot_size <= begin), "Invalid ART dependency range")
    sections = {}
    previous = 0
    for i, name in enumerate(SECTION_NAMES):
        off, length = struct.unpack_from("<2I", raw, 72+8*i)
        if name != "bitmap":
            require(off+length <= size, "ART section outside image: "+name)
            if length:
                require(off >= previous, "Overlapping ART sections")
                previous = off+length
        sections[name] = {"offset": off, "bytes": length}
    require(sections["objects"]["offset"] == 0 and sections["objects"]["bytes"] >= HEADER,
            "Invalid ART object section")
    data_size, blocks_offset, blocks_count = struct.unpack_from("<3I", raw, 240)
    require(data_size > 0 and HEADER+data_size <= len(raw), "Truncated ART stored data")
    bitmap_file_offset = (HEADER+data_size+PAGE-1)//PAGE*PAGE
    require(sections["bitmap"]["bytes"] > 0 and
            bitmap_file_offset+sections["bitmap"]["bytes"] == len(raw),
            "ART bitmap/file length mismatch")
    # The compressed block array lives in the uncompressed image. Do not
    # interpret it as file-backed bytes or claim block integrity.
    if blocks_count:
        require(blocks_count <= 65536 and HEADER <= blocks_offset
                and blocks_offset+20*blocks_count <= size, "ART block table outside image")
    else:
        require(blocks_offset == 0 and HEADER+data_size == size,
                "Invalid uncompressed ART data size")
    return {"version": "085", "isa": isa, "pointer_bytes": pointer,
            "reservation_bytes": reservation, "component_count": components,
            "image_begin": begin, "image_bytes": size, "reported_image_checksum": checksum,
            "reported_oat_checksum": oat_checksum, "oat_file_begin": oat_begin,
            "oat_data_begin": oat_data, "oat_data_end": oat_data_end, "oat_file_end": oat_end,
            "dependency_components": boot_components, "dependency_checksum": boot_checksum,
            "dependency_begin": boot_begin, "dependency_bytes": boot_size,
            "sections": sections, "stored_data_bytes": data_size,
            "compressed_block_count": blocks_count, "bitmap_file_offset": bitmap_file_offset,
            "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw),
            "image_checksum_verified": False, "compressed_blocks_verified": False,
            "object_graph_verified": False, "memory_mapping_verified": False}


def compare(image_raw, oat_raw, vdex_raw, isa, paths, artifacts):
    image = inspect_image(image_raw, isa)
    oat = compare_oat(oat_raw, vdex_raw, isa, paths, artifacts)
    checksum_matches = image["reported_oat_checksum"] == oat["oat"]["reported_oat_checksum"]
    passed = checksum_matches and oat["status"] == "OAT_VDEX_LITERAL_LOCATION_CHECKSUMS_MATCH_ONLY"
    return {"status": "ART_OAT_VDEX_LITERAL_HEADER_MATCH_ONLY" if passed else "REVIEW_REQUIRED",
            "image": image, "oat_vdex": oat, "reported_oat_checksum_matches": checksum_matches,
            "boot_image_dependencies_verified": False, "boot_image_verified": False,
            "art_initialization_verified": False, "hardware_tested": False, "safe_to_flash": False}
