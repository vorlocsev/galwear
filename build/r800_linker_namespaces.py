#!/usr/bin/env python3
"""Conservative offline inventory of generated Android linker configuration.

Not a linkerconfig generator or runtime namespace resolver.
"""
from __future__ import annotations

import re
from r800_android_userspace_preflight import guest_path, read_regular

MAX_CONFIG = 1024 * 1024
IDENT = re.compile(r"[A-Za-z0-9_-]{1,128}")
LIB = re.compile(r"[A-Za-z0-9_.+~-]{1,255}")
NS_KEY = re.compile(r"namespace\.([A-Za-z0-9_-]+)\.(.+)")
LINK_KEY = re.compile(r"link\.([A-Za-z0-9_-]+)\.(shared_libs|allow_all_shared_libs)")
PATH = re.compile(r"/[A-Za-z0-9_./+~\-\${}]*")
CONFIGS = ("/linkerconfig/ld.config.txt", "/system/etc/ld.config.txt",
           "/system/etc/ld.config.vndk_lite.txt", "/system/etc/ld.config.legacy.txt")


def split_list(value, sep):
    if not value:
        return []
    items = [item.strip() for item in value.split(sep)]
    if any(not item for item in items):
        raise ValueError("Empty namespace list item")
    return items


def path_list(value, abi):
    paths = []
    for item in split_list(value, ":"):
        item = item.replace("${LIB}", "lib64" if abi == "arm64" else "lib")
        if not PATH.fullmatch(item) or ".." in item.split("/") or "." in item.split("/"):
            raise ValueError("Invalid namespace path")
        paths.append(item.rstrip("/") or "/")
    return paths


def boolean(value):
    if value not in ("true", "false"):
        raise ValueError("Invalid namespace boolean")
    return value == "true"


def parse(text, abi):
    sections, directories, unknown = {}, {}, []
    current = None
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if len(line) > 16384:
            raise ValueError("Namespace config line exceeds limit")
        if line.startswith("[") and line.endswith("]"):
            current = line[1:-1]
            if not IDENT.fullmatch(current) or current in sections or len(sections) >= 128:
                raise ValueError("Invalid or duplicate namespace section")
            sections[current] = {}
            continue
        match = re.fullmatch(r"([A-Za-z0-9_.-]+)\s*(\+?=)\s*(.*)", line)
        if not match:
            raise ValueError("Invalid namespace assignment at line " + str(number))
        key, op, value = match.groups()
        if current is None:
            if not key.startswith("dir.") or not IDENT.fullmatch(key[4:]):
                unknown.append(key)
                continue
            target = directories
            key = key[4:]
        else:
            target = sections[current]
        if op == "+=":
            if key not in target:
                raise ValueError("Append without namespace base value")
            # Android uses colon lists for paths/shared libs and comma lists
            # for namespace names. Other append operations remain unsupported.
            suffix = key.rsplit(".", 1)[-1]
            if current is None:
                sep = ":"
            elif suffix in ("links", "additional.namespaces") or key == "additional.namespaces":
                sep = ","
            elif suffix in ("paths", "shared_libs"):
                sep = ":"
            else:
                raise ValueError("Unsupported namespace append")
            target[key] += (sep if target[key] and value else "") + value
        elif key in target:
            raise ValueError("Duplicate namespace property: " + key)
        else:
            target[key] = value

    result = {}
    for section, props in sections.items():
        names = ["default"] + split_list(props.get("additional.namespaces", ""), ",")
        if len(names) > 128 or len(set(names)) != len(names) or any(not IDENT.fullmatch(n) for n in names):
            raise ValueError("Invalid or duplicate namespace name")
        spaces = {n: {"isolated": None, "visible": None, "search_paths": [],
                      "permitted_paths": [], "links": [], "link_policies": {}} for n in names}
        for key, value in props.items():
            if key == "additional.namespaces":
                continue
            m = NS_KEY.fullmatch(key)
            if not m:
                unknown.append(section + ":" + key)
                continue
            name, prop = m.groups()
            if name not in spaces:
                raise ValueError("Undeclared namespace: " + name)
            ns = spaces[name]
            if prop in ("isolated", "visible"):
                ns[prop] = boolean(value)
            elif prop in ("search.paths", "permitted.paths"):
                ns[prop.replace(".", "_")] = path_list(value, abi)
            elif prop == "links":
                ns["links"] = split_list(value, ",")
                if len(set(ns["links"])) != len(ns["links"]):
                    raise ValueError("Duplicate namespace link")
            elif (link := LINK_KEY.fullmatch(prop)):
                dest, field = link.groups()
                policy = ns["link_policies"].setdefault(dest, {})
                if field == "allow_all_shared_libs":
                    policy[field] = boolean(value)
                else:
                    libs = split_list(value, ":")
                    if any(not LIB.fullmatch(lib) or lib in (".", "..") for lib in libs):
                        raise ValueError("Invalid shared library allowlist")
                    policy[field] = libs
            else:
                unknown.append(section + ":" + key)
        for name, ns in spaces.items():
            if any(dest not in spaces or dest == name for dest in ns["links"]):
                raise ValueError("Invalid namespace link destination")
            if set(ns["link_policies"]) - set(ns["links"]):
                raise ValueError("Policy for undeclared namespace link")
            for dest in ns["links"]:
                policy = ns["link_policies"].get(dest, {})
                if policy.get("allow_all_shared_libs") and policy.get("shared_libs"):
                    raise ValueError("Conflicting namespace link policy")
                if not policy.get("allow_all_shared_libs") and not policy.get("shared_libs"):
                    unknown.append(section + ":" + name + "->" + dest + ":no explicit allowlist")
        result[section] = spaces
    dirs = {name: path_list(value, abi) for name, value in directories.items()}
    if set(dirs) - set(result):
        raise ValueError("Directory maps to undefined namespace section")
    if not result:
        raise ValueError("No linker namespace sections")
    for section, spaces in result.items():
        for name, ns in spaces.items():
            if any(any(ch in path for ch in "${}") for path in ns["search_paths"] + ns["permitted_paths"]):
                unknown.append(section + ":" + name + ":unexpanded path variable")
    if any(any(ch in path for ch in "${}") for paths in dirs.values() for path in paths):
        unknown.append("directory_sections:unexpanded path variable")
    return {"sections": result, "directory_sections": dirs,
            "unsupported_properties": unknown, "runtime_resolution_verified": False}


def audit(root):
    configs, errors = {}, []
    for path in CONFIGS:
        try:
            data = read_regular(guest_path(root, path), MAX_CONFIG).decode("utf-8")
        except FileNotFoundError:
            continue
        except (OSError, ValueError) as exc:
            errors.append(path + ": " + str(exc))
            continue
        try:
            configs[path] = {abi: parse(data, abi) for abi in ("arm", "arm64")}
        except ValueError as exc:
            errors.append(path + ": " + str(exc))
    unsupported = any(v["unsupported_properties"] for config in configs.values() for v in config.values())
    return {"status": "CONFIG_INVENTORY_ONLY" if configs and not errors and not unsupported else "REVIEW_REQUIRED",
            "configs": configs, "errors": errors,
            "generated_config_present": CONFIGS[0] in configs,
            "runtime_resolution_verified": False, "safe_to_flash": False}
