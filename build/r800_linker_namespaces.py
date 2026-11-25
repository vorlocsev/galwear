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


MAX_SCOPE_STATES = 4096
MAX_SCOPE_PROBES = 32768
LIST_FILES = {
    "llndk": ("/system/etc/llndk.libraries.txt",),
    "vndk_core": ("/system/etc/vndkcore.libraries.txt",),
    "vndk_sp": ("/system/etc/vndksp.libraries.txt",),
}


def library_lists(root):
    """Optional legacy list evidence; absence is not proof of incompatibility."""
    lists, errors = {}, []
    for category, paths in LIST_FILES.items():
        for path in paths:
            try:
                data = read_regular(guest_path(root, path), MAX_CONFIG).decode("utf-8")
                names = set()
                for line in data.splitlines():
                    name = line.split("#", 1)[0].strip()
                    if not name:
                        continue
                    if not LIB.fullmatch(name) or name in (".", ".."):
                        raise ValueError("Unsupported library list entry")
                    names.add(name)
                    if len(names) > 8192:
                        raise ValueError("Library list exceeds inspection limit")
                lists[category] = {"path": path, "libraries": sorted(names)}
            except FileNotFoundError:
                continue
            except (OSError, ValueError) as exc:
                errors.append(path + ": " + str(exc))
    return {"lists": lists, "errors": errors, "runtime_policy_verified": False}


def section_for(config, executable):
    matches = [(len(directory), section)
               for section, dirs in config["directory_sections"].items()
               for directory in dirs
               if executable.startswith(directory.rstrip("/") + "/")]
    if not matches:
        return None
    longest = max(length for length, _ in matches)
    sections = {section for length, section in matches if length == longest}
    return next(iter(sections)) if len(sections) == 1 else None


def scope_candidates(root, inventory, seen, edges, targets):
    """Match configured direct search paths against previously inspected ELF edges.

    No runtime lookup order, global groups, dlopen, ASAN or APEX activation.
    A file found outside the ELF graph is reported as uninspected, not accepted.
    """
    config = inventory["configs"].get(CONFIGS[0])
    report = {"status": "REVIEW_REQUIRED", "roots": [], "checks": [],
              "errors": [], "runtime_resolution_verified": False,
              "legacy_library_lists": library_lists(root)}
    if not config:
        report["errors"].append("Generated linker configuration unavailable")
        return report
    probes = 0
    pending = []
    visited = set()
    for target in targets:
        info = seen.get(target)
        if info is None:
            report["errors"].append("Uninspected namespace root: " + target)
            continue
        parsed = config[info["abi"]]
        section = section_for(parsed, target)
        report["roots"].append({"path": target, "section": section})
        if section is None or parsed["unsupported_properties"]:
            report["errors"].append("Namespace section or properties require review: " + target)
            continue
        pending.append((info["abi"], section, "default", target))
    while pending:
        abi, section, namespace, path = pending.pop(0)
        state = (abi, section, namespace, path)
        if state in visited:
            continue
        if len(visited) >= MAX_SCOPE_STATES:
            report["errors"].append("Namespace state limit exceeded")
            break
        visited.add(state)
        spaces = config[abi]["sections"][section]
        ns = spaces[namespace]
        for dep, candidates in edges.get(path, {}).items():
            allowed = [namespace]
            denied = []
            for dest in ns["links"]:
                policy = ns["link_policies"].get(dest, {})
                if policy.get("allow_all_shared_libs") or dep in policy.get("shared_libs", []):
                    allowed.append(dest)
                else:
                    denied.append(dest)
            known = {}
            for candidate in candidates:
                try:
                    known[str(guest_path(root, candidate))] = candidate
                except (OSError, ValueError):
                    continue
            found, uninspected = [], []
            for dest in allowed:
                other = spaces[dest]
                for directory in other["search_paths"]:
                    probes += 1
                    if probes > MAX_SCOPE_PROBES:
                        report["errors"].append("Namespace probe limit exceeded")
                        return report
                    guest = directory.rstrip("/") + "/" + dep
                    try:
                        resolved = str(guest_path(root, guest))
                    except FileNotFoundError:
                        continue
                    except (OSError, ValueError) as exc:
                        report["errors"].append(guest + ": " + str(exc))
                        continue
                    candidate = known.get(resolved)
                    # Isolation and symlink realpath semantics need runtime evidence.
                    if candidate is None or seen.get(candidate) is None:
                        uninspected.append({"namespace": dest, "path": guest})
                        continue
                    item = {"namespace": dest, "path": guest, "elf_candidate": candidate}
                    if item not in found:
                        found.append(item)
                    next_state = (abi, section, dest, candidate)
                    if next_state not in visited and next_state not in pending:
                        pending.append(next_state)
            report["checks"].append({"from": path, "section": section, "namespace": namespace,
                                     "needed": dep, "candidates": found,
                                     "uninspected": uninspected, "denied_links": denied,
                                     "status": "STATIC_CANDIDATE_ONLY" if len(found) == 1 and not uninspected
                                     else "REVIEW_REQUIRED"})
            if len(report["checks"]) >= MAX_SCOPE_PROBES:
                report["errors"].append("Namespace report limit exceeded")
                return report
    if (report["roots"] and not report["errors"] and not report["legacy_library_lists"]["errors"]
            and all(c["status"] == "STATIC_CANDIDATE_ONLY" for c in report["checks"])):
        report["status"] = "STATIC_SCOPE_INVENTORY_ONLY"
    return report
