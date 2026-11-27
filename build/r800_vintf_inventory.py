#!/usr/bin/env python3
"""Bounded literal VINTF HAL inventory, not libvintf compatibility verification."""
from __future__ import annotations
import re
import xml.etree.ElementTree as ET
from r800_android_userspace_preflight import guest_path, read_regular

MAX_XML = 1024 * 1024
MAX_FILES = 128
MAX_ENTRIES = 4096
PARTITIONS = ("system", "system_ext", "product", "vendor", "odm")
NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_.]{0,254}")
INSTANCE = re.compile(r"[A-Za-z0-9_.:/-]{1,255}")


def version_range(text, kind):
    if kind == "hidl":
        m = re.fullmatch(r"([0-9]{1,5})\.([0-9]{1,5})(?:-([0-9]{1,5}))?", text)
        if m:
            major, low = int(m[1]), int(m[2])
            high = int(m[3]) if m[3] is not None else low
            if low <= high:
                return major, low, high
    elif kind == "aidl":
        m = re.fullmatch(r"([0-9]{1,5})(?:-([0-9]{1,5}))?", text)
        if m:
            low, high = int(m[1]), int(m[2] or m[1])
            if 1 <= low <= high:
                return 0, low, high
    raise ValueError("Unsupported HAL version or range: " + text)


def parse(data, source):
    text = data.decode("utf-8")
    # Reject DTD/entity declarations in the original input, including across PIs.
    # XML comments and CDATA do not enable external or internal entity definitions.
    if "<!DOCTYPE" in text or "<!ENTITY" in text or "\0" in text:
        raise ValueError("Unsupported VINTF XML declaration")
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        raise ValueError("Malformed VINTF XML") from exc
    if root.tag not in ("manifest", "compatibility-matrix") or root.get("type") not in ("device", "framework"):
        raise ValueError("Invalid VINTF root")
    matrix = root.tag == "compatibility-matrix"
    entries, review = [], []
    for hal in root:
        if hal.tag != "hal":
            review.append("Uninspected element: " + hal.tag)
            continue
        kind = hal.get("format", "hidl")
        name = (hal.findtext("name") or "").strip()
        if kind not in ("hidl", "aidl") or not NAME.fullmatch(name):
            review.append("Unsupported HAL: " + name)
            continue
        if hal.get("override") == "true":
            review.append("HAL override not merged: " + name)
        optional = hal.get("optional", "false")
        if optional not in ("true", "false"):
            raise ValueError("Invalid HAL optional attribute")
        transport = hal.findtext("transport")
        versions = [version_range((v.text or "").strip(), kind) for v in hal.findall("version")]
        if kind == "aidl" and not versions:
            versions = [(0, 1, 1)]
        for element in hal:
            if element.tag not in ("name", "version", "transport", "interface", "fqname"):
                review.append("Uninspected HAL element: " + element.tag)
        def add(interface, instance, ver):
            if not NAME.fullmatch(interface) or not INSTANCE.fullmatch(instance):
                raise ValueError("Invalid HAL interface or instance")
            if len(entries) >= MAX_ENTRIES:
                raise ValueError("VINTF entry limit exceeded")
            entries.append({"name": name, "format": kind, "interface": interface,
                            "instance": instance, "version": list(ver), "optional": optional == "true",
                            "transport": transport, "source": source})
        for interface in hal.findall("interface"):
            iface = (interface.findtext("name") or "").strip()
            if interface.findall("regex-instance"):
                review.append("Regex instance not evaluated: " + name)
            for instance in interface.findall("instance"):
                if not versions:
                    review.append("HAL version unavailable: " + name)
                for ver in versions:
                    add(iface, (instance.text or "").strip(), ver)
        for fqname in hal.findall("fqname"):
            raw = (fqname.text or "").strip()
            if kind == "hidl":
                m = re.fullmatch(r"@([0-9]+\.[0-9]+)::([^/]+)/(.+)", raw)
                if not m:
                    raise ValueError("Invalid HIDL fqname")
                add(m[2], m[3], version_range(m[1], kind))
            else:
                m = re.fullmatch(r"([^/]+)/(.+)", raw)
                if not m:
                    raise ValueError("Invalid AIDL fqname")
                for ver in versions:
                    add(m[1], m[2], ver)
        if not hal.findall("interface") and not hal.findall("fqname"):
            review.append("HAL without literal instance: " + name)
    return {"kind": root.tag, "type": root.get("type"), "level": root.get("level"),
            "target_level": root.get("target-level"), "entries": entries,
            "review": review, "matrix": matrix}


def matches(required, provided):
    keys = ("name", "format", "interface", "instance")
    if any(required[k] != provided[k] for k in keys):
        return False
    major, low, high = required["version"]
    pmajor, plow, phigh = provided["version"]
    return major == pmajor and max(low, plow) <= min(high, phigh)


def audit(root):
    files, errors = {}, []
    candidates = ["/vendor/manifest.xml", "/system/compatibility_matrix.xml"]
    scanned = 0
    for partition in PARTITIONS:
        base = "/" + partition + "/etc/vintf"
        candidates.extend((base + "/manifest.xml", base + "/compatibility_matrix.xml"))
        for directory in (base, base + "/manifest"):
            try:
                resolved = guest_path(root, directory)
                for entry in resolved.iterdir():
                    scanned += 1
                    if scanned > 4096:
                        raise ValueError("VINTF directory scan limit exceeded")
                    if entry.name.endswith(".xml") and (directory.endswith("/manifest") or
                            entry.name.startswith(("manifest_", "compatibility_matrix."))):
                        candidates.append(directory + "/" + entry.name)
                    if len(candidates) > MAX_FILES:
                        raise ValueError("VINTF candidate limit exceeded")
            except FileNotFoundError:
                continue
            except (OSError, ValueError) as exc:
                errors.append(directory + ": " + str(exc))
    count = 0
    for path in sorted(set(candidates))[:MAX_FILES]:
        try:
            doc = parse(read_regular(guest_path(root, path), MAX_XML), path)
            count += len(doc["entries"])
            if count > MAX_ENTRIES:
                raise ValueError("Aggregate VINTF entry limit exceeded")
            files[path] = doc
        except FileNotFoundError:
            continue
        except (OSError, ValueError) as exc:
            errors.append(path + ": " + str(exc))
            if count > MAX_ENTRIES:
                break
    provided = [entry for doc in files.values() if doc["kind"] == "manifest" and doc["type"] == "device"
                for entry in doc["entries"]]
    matrices = [doc for doc in files.values() if doc["matrix"] and doc["type"] == "framework"]
    comparisons = []
    for path, doc in files.items():
        if doc not in matrices:
            continue
        for req in doc["entries"]:
            found = any(matches(req, p) for p in provided)
            comparisons.append({"matrix": path, "requirement": req,
                                "status": "LITERAL_MATCH" if found else
                                "OPTIONAL_NOT_FOUND" if req["optional"] else "NO_LITERAL_MATCH"})
    return {"status": "LITERAL_INVENTORY_ONLY" if provided and matrices and not errors and
            not any(d["review"] for d in files.values()) and
            all(c["status"] != "NO_LITERAL_MATCH" for c in comparisons) else "REVIEW_REQUIRED",
            "files": files, "comparisons": comparisons, "errors": errors,
            "fcm_level_selection_verified": False, "manifest_merge_verified": False,
            "vintf_compatibility_verified": False, "hal_registration_verified": False,
            "safe_to_flash": False}
