#!/usr/bin/env python3
"""Offline APEX metadata inventory. Never mounts, activates or executes modules."""
from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET

from r800_android_userspace_preflight import guest_path, read_regular

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
            if manifest["name"] != name:
                errors.append(base + ": manifest name mismatch")
            if name in active:
                entry["version_consistent"] = manifest["version"] == active[name]["version"]
                if not entry["version_consistent"]:
                    errors.append(base + ": manifest version mismatch")
        except FileNotFoundError:
            pass
        except (OSError, ValueError) as exc:
            errors.append(base + ": " + str(exc))
        try:
            read_regular(guest_path(root, base + "/apex_manifest.pb"), MAX_METADATA)
            entry["protobuf_manifest_present"] = True
        except FileNotFoundError:
            pass
        except (OSError, ValueError) as exc:
            errors.append(base + ": " + str(exc))
        if entry["json_manifest"] is None:
            errors.append(base + ": JSON manifest unavailable; protobuf not decoded")
        if name not in active:
            errors.append(base + ": active metadata unavailable")
    return {"status": "METADATA_INVENTORY_ONLY" if not errors else "REVIEW_REQUIRED",
            "modules": modules, "records": records, "errors": errors,
            "apexd_activation_verified": False, "signature_verified": False,
            "mounts_verified": False, "safe_to_flash": False}
