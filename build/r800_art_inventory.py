#!/usr/bin/env python3
"""Read-only ART classpath and standard DEX inventory; no bytecode execution."""
from __future__ import annotations
import hashlib
import io
import re
import struct
import zipfile
import zlib

from r800_android_userspace_preflight import guest_path, read_regular

MAX_JAR = 64 * 1024 * 1024
MAX_DEX = 64 * 1024 * 1024
MAX_TOTAL = 256 * 1024 * 1024
MAX_PATHS = 128
CLASSPATHS = ("BOOTCLASSPATH", "DEX2OATBOOTCLASSPATH", "SYSTEMSERVERCLASSPATH")
DEX_NAME = re.compile(r"classes(?:[2-9]|[1-9][0-9]+)?\.dex")


def dex_inventory(data):
    if (not 112 <= len(data) <= MAX_DEX or
            data[:4] != b"dex\n" or data[7] != 0 or
            data[4:7] not in (b"035", b"037", b"038", b"039", b"040")):
        raise ValueError("Unsupported or invalid standard DEX header")
    file_size, header_size, endian = struct.unpack_from("<III", data, 32)
    if file_size != len(data) or header_size != 112 or endian != 0x12345678:
        raise ValueError("Invalid DEX size or endian tag")
    if hashlib.sha1(data[32:]).digest() != data[12:32]:
        raise ValueError("DEX SHA-1 mismatch")
    if zlib.adler32(data[12:]) & 0xffffffff != struct.unpack_from("<I", data, 8)[0]:
        raise ValueError("DEX Adler-32 mismatch")
    sections = {}
    ranges = []
    for name, offset, width in (("string_ids", 56, 4), ("type_ids", 64, 4),
            ("proto_ids", 72, 12), ("field_ids", 80, 8),
            ("method_ids", 88, 8), ("class_defs", 96, 32), ("data", 104, 1)):
        count, start = struct.unpack_from("<II", data, offset)
        if (not count and start or count and
                (start < 112 or start % 4 or count * width > len(data) - start)):
            raise ValueError("Invalid DEX section: " + name)
        if count:
            ranges.append((start, start + count * width))
        sections[name] = count
    ranges.sort()
    if any(a[1] > b[0] for a, b in zip(ranges, ranges[1:])):
        raise ValueError("Overlapping DEX sections")
    data_size, data_off = struct.unpack_from("<II", data, 104)
    map_off = struct.unpack_from("<I", data, 52)[0]
    if not data_size or not data_off <= map_off <= data_off + data_size - 4 or map_off % 4:
        raise ValueError("Invalid DEX map offset")
    map_count = struct.unpack_from("<I", data, map_off)[0]
    if not 1 <= map_count <= 4096 or map_off + 4 + 12 * map_count > data_off + data_size:
        raise ValueError("Invalid DEX map size")
    return {"version": data[4:7].decode("ascii"), "bytes": len(data),
            "sections": sections, "map_entries": map_count,
            "checksum_matches": True, "bytecode_verified": False}


def jar_inventory(data, budget):
    if not 22 <= len(data) <= MAX_JAR:
        raise ValueError("Invalid JAR size")
    end = data.rfind(b"PK\x05\x06", max(0, len(data) - 65557))
    if end < 0 or end + 22 > len(data):
        raise ValueError("JAR ZIP directory missing")
    disk, cd_disk, disk_count, count, size, offset, comment = struct.unpack_from("<4H2IH", data, end + 4)
    if (disk or cd_disk or disk_count != count or not 1 <= count <= 8192 or
            size > 4 * 1024 * 1024 or offset + size != end or end + 22 + comment != len(data)):
        raise ValueError("Unsupported JAR ZIP directory")
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        entries = archive.infolist()
        if len(entries) != count or len({e.filename for e in entries}) != count:
            raise ValueError("Duplicate or inconsistent JAR entries")
        dex = [e for e in entries if DEX_NAME.fullmatch(e.filename)]
        if not dex:
            return {"status": "NO_EMBEDDED_DEX", "dex": {}}, 0
        if len(dex) > 64:
            raise ValueError("Multidex entry limit exceeded")
        expected = {"classes.dex"} | {"classes" + str(i) + ".dex" for i in range(2, len(dex) + 1)}
        if {e.filename for e in dex} != expected:
            raise ValueError("Noncontiguous multidex entries")
        total = sum(e.file_size for e in dex)
        if total > budget:
            raise ValueError("ART aggregate DEX budget exceeded")
        result = {}
        for item in dex:
            if (item.flag_bits & 1 or not 112 <= item.file_size <= MAX_DEX or
                    item.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)):
                raise ValueError("Unsupported DEX ZIP entry")
            result[item.filename] = dex_inventory(archive.read(item))
        return {"status": "DEX_HEADER_INVENTORY_ONLY", "dex": result}, total


def audit(root, init):
    values = {key: [] for key in CLASSPATHS}
    errors, artifacts = [], {}
    total = 0
    for item in init["art_environment"]:
        args = item["args"]
        if args and args[0] in values:
            if len(args) != 2:
                errors.append("Invalid classpath export: " + args[0])
            elif args[1] not in values[args[0]]:
                values[args[0]].append(args[1])
    if not values["BOOTCLASSPATH"]:
        errors.append("BOOTCLASSPATH export unavailable")
    for key, options in values.items():
        if len(options) > 1:
            errors.append("Multiple static exports: " + key)
        for option in options:
            paths = option.split(":")
            if len(paths) > MAX_PATHS or len(set(paths)) != len(paths):
                errors.append("Invalid classpath list: " + key)
                continue
            for path in paths:
                if path in artifacts:
                    continue
                if len(artifacts) >= MAX_PATHS:
                    errors.append("ART classpath path limit exceeded")
                    return report(values, artifacts, errors)
                if (not path.startswith("/") or not path.endswith((".jar", ".dex")) or
                        ".." in path.split("/") or any(ch in path for ch in "$*?{}[]")):
                    errors.append("Unresolved classpath entry: " + path)
                    continue
                artifacts[path] = None
                try:
                    raw = read_regular(guest_path(root, path), MAX_JAR)
                    total += len(raw)
                    if total > MAX_TOTAL:
                        raise ValueError("ART aggregate input limit exceeded")
                    if path.endswith(".dex"):
                        result, used = {"status": "DEX_HEADER_INVENTORY_ONLY",
                                        "dex": {path: dex_inventory(raw)}}, 0
                    else:
                        result, used = jar_inventory(raw, MAX_TOTAL - total)
                    total += used
                    artifacts[path] = result
                    if result["status"] == "NO_EMBEDDED_DEX":
                        errors.append(path + ": no embedded DEX; precompiled evidence required")
                except (OSError, ValueError, RuntimeError, zipfile.BadZipFile, NotImplementedError) as exc:
                    errors.append(path + ": " + str(exc))
                    if total > MAX_TOTAL:
                        return report(values, artifacts, errors)
    return report(values, artifacts, errors)


def report(values, artifacts, errors):
    return {"status": "STATIC_DEX_INVENTORY_ONLY" if not errors else "REVIEW_REQUIRED",
            "classpath_exports": values, "artifacts": artifacts, "errors": errors,
            "oat_verified": False, "vdex_verified": False, "bytecode_verified": False,
            "art_initialization_verified": False, "safe_to_flash": False}
