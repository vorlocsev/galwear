#!/usr/bin/env python3
"""Bounded static SELinux policy inventory. Never loads or changes policy."""
from __future__ import annotations

import hashlib
import re
import struct

from r800_android_userspace_preflight import guest_path, read_regular

PARTITIONS = ("system", "system_ext", "product", "vendor", "odm")
MAX_POLICY = 32 * 1024 * 1024
MAX_TEXT = 4 * 1024 * 1024
MAX_TOTAL = 64 * 1024 * 1024
MAX_FILES = 128
MAX_SCAN = 4096
CONTEXT = re.compile(r"[A-Za-z0-9_]+:[A-Za-z0-9_]+:[A-Za-z0-9_]+:[A-Za-z0-9_:.,-]+")
VERSION = re.compile(r"[0-9]{1,4}\.[0-9]{1,4}")
FILE = re.compile(r"(?:[A-Za-z0-9_.-]+(?:_sepolicy\.cil|_contexts|_sepolicy\.vers)|[0-9]+\.[0-9]+(?:\.compat)?\.cil|precompiled_sepolicy(?:\.[A-Za-z0-9_.-]+)?|file_contexts|service_contexts|hwservice_contexts|property_contexts|vndservice_contexts|seapp_contexts|plat_sepolicy_vers\.txt)")
KERNEL_KEYS = ("CONFIG_SECURITY", "CONFIG_SECURITY_SELINUX", "CONFIG_SECURITY_SELINUX_BOOTPARAM",
               "CONFIG_SECURITY_SELINUX_DEVELOP", "CONFIG_AUDIT", "CONFIG_SECURITYFS")


def policy_header(data):
    if len(data) < 16:
        raise ValueError("Truncated binary policy header")
    magic, length = struct.unpack_from("<II", data)
    if magic != 0xf97cff8c or length != 8 or data[8:16] != b"SE Linux" or len(data) < 32:
        raise ValueError("Invalid binary SELinux policy header")
    version, config, symbols, objects = struct.unpack_from("<IIII", data, 16)
    if not 1 <= version <= 255 or not symbols or not objects:
        raise ValueError("Invalid binary policy metadata")
    return {"version": version, "config_bits": config, "symbol_tables": symbols,
            "object_context_tables": objects, "sha256": hashlib.sha256(data).hexdigest()}


def contexts(raw, kind):
    result = {"records": 0, "types": [], "duplicates": [], "unsupported_lines": 0}
    types, seen = set(), {}
    for line in raw.decode("utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        fields = line.split()
        result["records"] += 1
        if result["records"] > 65536:
            raise ValueError("SELinux context record limit exceeded")
        if kind == "seapp_contexts":
            for field in fields:
                if field.startswith(("domain=", "type=")):
                    types.add(field.split("=", 1)[1])
            continue
        found = [field for field in fields[1:] if CONTEXT.fullmatch(field)]
        if len(found) != 1:
            result["unsupported_lines"] += 1
            continue
        label = found[0]
        # File regexes and property prefix/exact rules can intentionally overlap.
        # Only report conflicting identical literal service names here.
        if kind in ("service_contexts", "hwservice_contexts", "vndservice_contexts"):
            if fields[0] in seen and seen[fields[0]] != label:
                result["duplicates"].append(fields[0])
            seen[fields[0]] = label
        types.add(label.split(":")[2])
    result["types"] = sorted(types)
    return result


def audit(root, init, kernel_config=None):
    errors, files, version_markers, policy_versions = [], {}, {}, {}
    paths = ["/sepolicy", "/file_contexts", "/service_contexts", "/property_contexts"]
    scanned = 0
    for partition in PARTITIONS:
        for suffix in ("/etc/selinux", "/etc/selinux/mapping"):
            base = "/" + partition + suffix
            try:
                for entry in guest_path(root, base).iterdir():
                    scanned += 1
                    if scanned > MAX_SCAN or len(paths) >= MAX_FILES:
                        raise ValueError("SELinux inventory scan limit exceeded")
                    if FILE.fullmatch(entry.name):
                        paths.append(base + "/" + entry.name)
            except FileNotFoundError:
                continue
            except (OSError, ValueError) as exc:
                errors.append(base + ": " + str(exc))
    total = 0
    for name in sorted(set(paths)):
        try:
            path = guest_path(root, name)
            length = path.lstat().st_size
            if total + length > MAX_TOTAL:
                raise ValueError("SELinux aggregate budget exceeded")
            basename = name.rsplit("/", 1)[-1]
            binary = basename in ("sepolicy", "precompiled_sepolicy")
            raw = read_regular(path, MAX_POLICY if binary else MAX_TEXT)
            total += len(raw)
            item = {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
            if binary:
                item["binary_header"] = policy_header(raw)
                policy_versions[name] = item["binary_header"]["version"]
            elif basename.endswith(("_sepolicy.vers", "_sepolicy_vers.txt")):
                value = raw.decode("ascii").strip()
                if not VERSION.fullmatch(value):
                    raise ValueError("Invalid platform policy version marker")
                version_markers[name] = value
            elif basename.endswith(".cil"):
                # Presence and digest only. CIL linking and neverallow checks require SELinux tooling.
                item["cil_compiled"] = False
            elif basename.endswith("_contexts"):
                kind = next((k for k in ("hwservice_contexts", "vndservice_contexts",
                            "service_contexts", "file_contexts", "property_contexts", "seapp_contexts")
                            if basename.endswith(k)), None)
                if kind:
                    item["context_inventory"] = contexts(raw, kind)
            files[name] = item
        except FileNotFoundError:
            continue
        except (OSError, ValueError) as exc:
            errors.append(name + ": " + str(exc))
    enforcing = None
    try:
        raw = read_regular(guest_path(root, "/sys/fs/selinux/enforce"), 16).strip()
        if raw not in (b"0", b"1"):
            raise ValueError("Invalid SELinux enforce snapshot")
        enforcing = raw == b"1"
    except FileNotFoundError:
        pass
    except (OSError, ValueError) as exc:
        errors.append(str(exc))
    seclabels = []
    for service in init.get("services", []):
        for option in service["options"]:
            if option["name"] == "seclabel":
                args = option["args"]
                valid = len(args) == 1 and bool(CONTEXT.fullmatch(args[0]))
                seclabels.append({"service": service["name"], "valid_syntax": valid})
                if not valid:
                    errors.append("Invalid init seclabel: " + service["name"])
    context_review = [path for path, item in files.items() if
                      item.get("context_inventory", {}).get("duplicates") or
                      item.get("context_inventory", {}).get("unsupported_lines")]
    kernel = None if kernel_config is None else {k: kernel_config.get(k) for k in KERNEL_KEYS}
    has_contexts = any(path.endswith("file_contexts") for path in files)
    return {"status": "STATIC_SELINUX_INVENTORY_ONLY" if not errors and not context_review and
            policy_versions and has_contexts and kernel and kernel["CONFIG_SECURITY_SELINUX"] == "y"
            and enforcing is not False else "REVIEW_REQUIRED",
            "files": files, "platform_version_markers": version_markers,
            "binary_policy_versions": policy_versions, "context_review": context_review,
            "init_seclabels": seclabels, "enforcing_snapshot": enforcing,
            "kernel_config": kernel, "errors": errors,
            "policy_compiled_verified": False, "policy_loaded_verified": False,
            "neverallow_verified": False, "domain_transitions_verified": False,
            "runtime_enforcing_verified": False, "safe_to_flash": False}
