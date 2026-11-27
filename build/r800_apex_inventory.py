#!/usr/bin/env python3
"""Offline APEX metadata inventory. Never mounts, activates or executes modules."""
from __future__ import annotations

import json
import hashlib
import stat
import struct
import zipfile
import re
import xml.etree.ElementTree as ET

from r800_android_userspace_preflight import guest_path, read_regular
import r800_avb_inventory

MAX_METADATA = 1024 * 1024
MAX_MODULES = 512
NAME = re.compile(r"com\.[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)+")
REQUIRED = ("com.android.runtime", "com.android.art")


def module_name(value):
    if not isinstance(value, str) or len(value) > 255 or not NAME.fullmatch(value):
        raise ValueError("Invalid APEX module name")
    return value


def version(value):
    if type(value) is int:
        n = value
    elif isinstance(value, str) and re.fullmatch(r"[0-9]{1,19}", value):
        n = int(value)
    else:
        raise ValueError("Invalid APEX version")
    if not 0 <= n <= (1 << 63) - 1:
        raise ValueError("APEX version outside range")
    return n


def flag(value):
    if value not in ("true", "false"):
        raise ValueError("Invalid APEX boolean")
    return value == "true"


def info_list(data):
    # Reject declarations before XML parsing, including UTF-16 encodings.
    text = data.decode("utf-8")
    if "<!" in text or "\0" in text:
        raise ValueError("Unsupported APEX XML declaration")
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        raise ValueError("Malformed APEX info XML") from exc
    if root.tag != "apex-info-list" or len(root) > MAX_MODULES:
        raise ValueError("Invalid APEX info list")
    result, active = [], set()
    for node in root:
        if node.tag != "apex-info" or len(node):
            raise ValueError("Invalid APEX info entry")
        name = module_name(node.get("moduleName"))
        item = {"name": name, "version": version(node.get("versionCode")),
                "active": flag(node.get("isActive")),
                "factory": flag(node.get("isFactory")),
                "module_path": node.get("modulePath")}
        if item["active"]:
            if name in active:
                raise ValueError("Duplicate active APEX: " + name)
            active.add(name)
        result.append(item)
    return result


def json_manifest(data):
    def unique(pairs):
        out = {}
        for key, value in pairs:
            if key in out:
                raise ValueError("Duplicate APEX manifest key")
            out[key] = value
        return out
    try:
        obj = json.loads(data.decode("utf-8"), object_pairs_hook=unique)
    except (json.JSONDecodeError, RecursionError) as exc:
        raise ValueError("Malformed APEX manifest JSON") from exc
    if not isinstance(obj, dict):
        raise ValueError("Invalid APEX manifest object")
    return {"name": module_name(obj.get("name")), "version": version(obj.get("version"))}


def protobuf_manifest(data):
    """Decode ApexManifest name (1) and version (2); skip bounded unknown fields."""
    if not 0 < len(data) <= MAX_METADATA:
        raise ValueError("Invalid APEX protobuf size")
    pos = 0

    def varint():
        nonlocal pos
        value = 0
        for i in range(10):
            if pos >= len(data):
                raise ValueError("Truncated APEX protobuf varint")
            b = data[pos]
            pos += 1
            if i == 9 and b > 1:
                raise ValueError("APEX protobuf varint overflow")
            value |= (b & 127) << (7 * i)
            if b < 128:
                return value
        raise ValueError("APEX protobuf varint overflow")

    fields = {}
    count = 0
    while pos < len(data):
        count += 1
        if count > 8192:
            raise ValueError("APEX protobuf field limit exceeded")
        key = varint()
        field, wire = key >> 3, key & 7
        if not 1 <= field < (1 << 29):
            raise ValueError("Invalid APEX protobuf field")
        if field in (1, 2):
            if field in fields or wire != (2 if field == 1 else 0):
                raise ValueError("Invalid or duplicate APEX protobuf identity field")
        if wire == 0:
            value = varint()
        elif wire in (1, 2, 5):
            size = varint() if wire == 2 else 8 if wire == 1 else 4
            if size > len(data) - pos:
                raise ValueError("Truncated APEX protobuf field")
            value = data[pos:pos + size]
            pos += size
        else:
            raise ValueError("Unsupported APEX protobuf wire type")
        if field in (1, 2):
            fields[field] = value
    if set(fields) != {1, 2}:
        raise ValueError("APEX protobuf identity missing")
    return {"name": module_name(fields[1].decode("utf-8")), "version": version(fields[2])}


MAX_APEX_BYTES = 2 * 1024 * 1024 * 1024


def package_inventory(path):
    """Inspect classic, non-ZIP64 APEX without extracting or reading full payload."""
    st = path.lstat()
    if not stat.S_ISREG(st.st_mode) or not 22 <= st.st_size <= MAX_APEX_BYTES:
        raise ValueError("Invalid APEX package size or type")
    with path.open("rb") as stream:
        # Bound the central directory before zipfile allocates its entries.
        tail_size = min(st.st_size, 65557)
        stream.seek(-tail_size, 2)
        tail = stream.read(tail_size)
        end = tail.rfind(b"PK\x05\x06")
        if end < 0 or len(tail) - end < 22:
            raise ValueError("APEX ZIP end record missing")
        disk, cd_disk, disk_count, count, cd_size, cd_offset, comment = struct.unpack_from("<4H2IH", tail, end + 4)
        eocd_offset = st.st_size - tail_size + end
        if (disk or cd_disk or disk_count != count or not 1 <= count <= 128 or
                cd_size > MAX_METADATA or cd_offset + cd_size != eocd_offset or
                end + 22 + comment != len(tail)):
            raise ValueError("Unsupported APEX ZIP directory")
        with zipfile.ZipFile(stream) as archive:
            entries = archive.infolist()
            by_name = {i.filename: i for i in entries}
            if len(entries) != count or len(by_name) != count:
                raise ValueError("Duplicate or inconsistent APEX ZIP entries")
            required = {"AndroidManifest.xml", "apex_payload.img", "apex_pubkey"}
            if not required <= by_name.keys() or not ({"apex_manifest.pb", "apex_manifest.json"} & by_name.keys()):
                raise ValueError("Required APEX entries missing")
            regions = []
            for item in entries:
                if (not item.filename or item.filename.startswith("/") or "\\" in item.filename or
                        ".." in item.filename.split("/") or item.flag_bits & 1):
                    raise ValueError("Unsafe APEX ZIP entry")
                if item.header_offset < 0 or item.header_offset + 30 > cd_offset:
                    raise ValueError("APEX local header outside archive")
                stream.seek(item.header_offset)
                header = stream.read(30)
                if len(header) != 30 or header[:4] != b"PK\x03\x04":
                    raise ValueError("Invalid APEX ZIP local header")
                name_len, extra_len = struct.unpack_from("<HH", header, 26)
                payload_offset = item.header_offset + 30 + name_len + extra_len
                if payload_offset + item.compress_size > cd_offset:
                    raise ValueError("APEX ZIP entry exceeds data area")
                regions.append((item.header_offset, payload_offset + item.compress_size))
                if item.filename == "apex_payload.img":
                    image_offset = payload_offset
            regions.sort()
            if any(a[1] > b[0] for a, b in zip(regions, regions[1:])):
                raise ValueError("Overlapping APEX ZIP entries")
            payload = by_name["apex_payload.img"]
            if payload.compress_type != zipfile.ZIP_STORED or payload.compress_size != payload.file_size:
                raise ValueError("Compressed APEX payload unsupported")
            if image_offset % 4096 or payload.file_size < 4096:
                raise ValueError("Invalid APEX payload alignment or size")

            def small(name):
                item = by_name[name]
                if not 0 < item.file_size <= MAX_METADATA:
                    raise ValueError("Invalid APEX metadata entry size")
                return archive.read(item)

            manifests = {}
            for name, parser in (("apex_manifest.pb", protobuf_manifest),
                                 ("apex_manifest.json", json_manifest)):
                if name in by_name:
                    manifests[name] = parser(small(name))
            identities = list(manifests.values())
            if any(m != identities[0] for m in identities):
                raise ValueError("APEX package manifests disagree")
            key = small("apex_pubkey")
            small("AndroidManifest.xml")
            with archive.open(payload) as image:
                head = image.read(1082)
            if head[1080:1082] != b"\x53\xef":
                raise ValueError("APEX payload lacks ext4 magic")
            avb = r800_avb_inventory.inspect(stream, image_offset, payload.file_size, key)
            return {"identity": identities[0], "entries": sorted(by_name),
                    "avb": avb,
                    "payload_bytes": payload.file_size, "payload_offset": image_offset,
                    "payload_ext4_magic": True, "pubkey_sha256": hashlib.sha256(key).hexdigest(),
                    "payload_crc_verified": False, "signature_verified": False}


def audit(root):
    errors, modules = [], {}
    records = None
    try:
        records = info_list(read_regular(guest_path(root, "/apex/apex-info-list.xml"), MAX_METADATA))
    except FileNotFoundError:
        errors.append("APEX info list unavailable")
    except (OSError, ValueError) as exc:
        errors.append("apex-info-list.xml: " + str(exc))
    active = {r["name"]: r for r in records or [] if r["active"]}
    names = set(REQUIRED) | set(active)
    for name in sorted(names):
        entry = {"active_record": active.get(name), "expanded_tree_present": False,
                 "json_manifest": None, "protobuf_manifest_present": False,
                 "protobuf_manifest": None, "package": None, "package_error": None,
                 "version_consistent": None}
        modules[name] = entry
        base = "/apex/" + name
        try:
            path = guest_path(root, base)
            if not path.is_dir():
                raise ValueError("APEX tree is not a directory")
            entry["expanded_tree_present"] = True
        except (OSError, ValueError) as exc:
            errors.append(base + ": " + str(exc))
            continue
        try:
            manifest = json_manifest(read_regular(guest_path(root, base + "/apex_manifest.json"), MAX_METADATA))
            entry["json_manifest"] = manifest
        except FileNotFoundError:
            pass
        except (OSError, ValueError) as exc:
            errors.append(base + ": " + str(exc))
        try:
            raw = read_regular(guest_path(root, base + "/apex_manifest.pb"), MAX_METADATA)
            entry["protobuf_manifest_present"] = True
            entry["protobuf_manifest"] = protobuf_manifest(raw)
        except FileNotFoundError:
            pass
        except (OSError, ValueError) as exc:
            errors.append(base + ": " + str(exc))
        identities = [m for m in (entry["json_manifest"], entry["protobuf_manifest"]) if m is not None]
        if not identities:
            errors.append(base + ": valid manifest unavailable")
        if identities and any(m != identities[0] for m in identities):
            errors.append(base + ": JSON and protobuf manifests disagree")
        if any(m["name"] != name for m in identities):
            errors.append(base + ": manifest name mismatch")
        if name in active and identities:
            entry["version_consistent"] = all(m["version"] == active[name]["version"] for m in identities)
            if not entry["version_consistent"]:
                errors.append(base + ": manifest version mismatch")
        package = active.get(name, {}).get("module_path")
        if isinstance(package, str) and package.endswith(".apex"):
            try:
                if not package.startswith("/") or ".." in package.split("/"):
                    raise ValueError("Invalid guest APEX package path")
                entry["package"] = package_inventory(guest_path(root, package))
                if entry["package"]["identity"] != {"name": name, "version": active[name]["version"]}:
                    raise ValueError("APEX package identity mismatch")
            except (OSError, ValueError, RuntimeError, zipfile.BadZipFile, NotImplementedError) as exc:
                entry["package_error"] = str(exc)
        if name not in active:
            errors.append(base + ": active metadata unavailable")
    return {"status": "METADATA_INVENTORY_ONLY" if not errors else "REVIEW_REQUIRED",
            "modules": modules, "records": records, "errors": errors,
            "package_status": "REVIEW_REQUIRED" if any(m["package"] is None or m["package_error"] for m in modules.values()) else "PACKAGE_STRUCTURE_ONLY",
            "avb_status": "AVB_STRUCTURE_ONLY" if modules and all(m["package"] and not m["package_error"] and m["package"]["avb"]["status"] == "AVB_STRUCTURE_ONLY" for m in modules.values()) else "REVIEW_REQUIRED",
            "apexd_activation_verified": False, "signature_verified": False,
            "mounts_verified": False, "safe_to_flash": False}
