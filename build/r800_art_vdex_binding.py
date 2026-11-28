#!/usr/bin/env python3
"""Android 11 VDEX 021 layout and ordered ART location checksum comparison.

Based on Android 11 r48 runtime/vdex_file.h and libdexfile/dex/dex_file_loader.cc.
No verification of embedded code, verifier deps, quickening, or ART execution.
"""
import hashlib
import re
import struct

from r800_extract_super import require

MAX_VDEX = 128*1024**2
MAX_FILES = 128
DEX_ENTRY = re.compile(r"classes(?:[2-9]|[1-9][0-9]+)?\.dex")


def inspect_vdex(raw):
    require(28 <= len(raw) <= MAX_VDEX and raw[:8] == b"vdex021\0",
            "Unsupported Android 11 VDEX header")
    section = raw[8:12]
    require(section in (b"000\0", b"002\0"), "Unsupported VDEX DEX section version")
    count, verifier, boot, context = struct.unpack_from("<4I", raw, 12)
    require(1 <= count <= MAX_FILES and 28+count*4 <= len(raw), "Invalid VDEX checksum table")
    checksums = list(struct.unpack_from("<"+"I"*count, raw, 28))
    end = 28+count*4
    dex_size = shared = quickening = 0
    if section == b"002\0":
        require(end+12 <= len(raw), "Truncated VDEX DEX section header")
        dex_size, shared, quickening = struct.unpack_from("<3I", raw, end)
        require(dex_size > 0, "Empty declared VDEX DEX section")
        end += 12+dex_size+shared
    end += verifier+quickening+boot+context
    require(end == len(raw), "VDEX declared sections do not match file length")
    return {"version": "021", "dex_section_version": section[:3].decode("ascii"),
            "location_checksums": checksums, "dex_section_bytes": dex_size,
            "dex_shared_data_bytes": shared, "quickening_bytes": quickening,
            "verifier_deps_bytes": verifier, "boot_classpath_checksum_bytes": boot,
            "class_loader_context_bytes": context, "sha256": hashlib.sha256(raw).hexdigest(),
            "bytes": len(raw), "embedded_dex_verified": False, "verifier_deps_verified": False}


def expected_checksums(paths, artifacts):
    require(1 <= len(paths) <= MAX_FILES and len(set(paths)) == len(paths),
            "Explicit unique ordered DEX locations required")
    values = []
    for path in paths:
        row = artifacts.get(path)
        require(isinstance(row, dict) and row.get("status") == "DEX_HEADER_INVENTORY_ONLY",
                "Missing DEX header evidence: "+path)
        dex = row.get("dex")
        require(isinstance(dex, dict) and dex, "Missing embedded DEX: "+path)
        if path.endswith(".jar"):
            require(all(DEX_ENTRY.fullmatch(n) for n in dex), "Invalid multidex names")
            names = ["classes.dex"]+["classes"+str(i)+".dex" for i in range(2,len(dex)+1)]
            require(set(names) == set(dex), "Noncontiguous multidex")
            kind = "ZIP_ENTRY_CRC32"
        elif path.endswith(".dex"):
            require(set(dex) == {path}, "Invalid standalone DEX evidence")
            names, kind = [path], "DEX_HEADER_ADLER32"
        else:
            raise ValueError("Unsupported DEX location")
        for name in names:
            item = dex[name]
            checksum = item.get("location_checksum")
            require(item.get("checksum_matches") is True and
                    item.get("location_checksum_kind") == kind and
                    type(checksum) is int and 0 <= checksum <= 0xffffffff,
                    "Invalid ART location checksum evidence")
            values.append({"path": path, "entry": name, "kind": kind, "checksum": checksum})
            require(len(values) <= MAX_FILES, "Aggregate DEX count exceeded")
    return values


def compare(raw, paths, artifacts):
    vdex = inspect_vdex(raw)
    expected = expected_checksums(paths, artifacts)
    matches = vdex["location_checksums"] == [row["checksum"] for row in expected]
    return {"status": "VDEX_ORDERED_LOCATION_CHECKSUMS_MATCH_ONLY" if matches else "REVIEW_REQUIRED",
            "vdex": vdex, "expected": expected, "ordered_checksums_match": matches,
            "dex_location_identity_verified": False, "oat_compatibility_verified": False,
            "vdex_verified": False, "boot_classpath_context_verified": False,
            "art_initialization_verified": False, "safe_to_flash": False}
