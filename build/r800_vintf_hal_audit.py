#!/usr/bin/env python3
"""Offline VINTF declaration inventory, not a replacement for libvintf/checkvintf."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import re
import xml.etree.ElementTree as ET

from r800_android_userspace_preflight import guest_path, read_regular

MAX_XML = 1024 * 1024
MAX_FILES = 256
MAX_HAL = 2048
PARTITIONS = ("system", "system_ext", "product", "vendor", "odm")
PACKAGE = re.compile(r"[A-Za-z_][A-Za-z0-9_.]*")
IFACE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
INSTANCE = re.compile(r"[A-Za-z0-9_.+-]+")


def version_range(text, fmt):
    if fmt == "hidl":
        m = re.fullmatch(r"([0-9]{1,5})\.([0-9]{1,5})(?:-([0-9]{1,5}))?", text)
        if not m:
            raise ValueError("Unsupported HIDL version: " + text)
        major, low, high = m.groups()
        a, b = (int(major), int(low)), (int(major), int(high or low))
    else:
        m = re.fullmatch(r"([0-9]{1,5})(?:-([0-9]{1,5}))?", text)
        if not m:
            raise ValueError("Unsupported AIDL version: " + text)
        low, high = m.groups()
        a, b = (int(low),), (int(high or low),)
    if a > b:
        raise ValueError("Reversed version range")
    return a, b


def strings(node, tag):
    return [(e.text or "").strip() for e in node.findall(tag)]


def safe_name(text, pattern):
    if not pattern.fullmatch(text):
        raise ValueError("Unsupported declaration name: " + text)
    return text


def parse_document(data, source):
    # UTF-8 only: reject alternate encodings and any DTD/entity declaration.
    text = data.decode("utf-8")
    if "\x00" in text or re.search(r"<!\s*(DOCTYPE|ENTITY)", text, re.I):
        raise ValueError("DTD, entity or NUL forbidden")
    root = ET.fromstring(text)
    if root.tag not in ("manifest", "compatibility-matrix"):
        raise ValueError("Not a VINTF document")
    kind = root.tag
    side = root.get("type")
    if side not in ("device", "framework"):
        raise ValueError("Unknown VINTF document type")
    hals, unsupported = [], []
    for hal in root.findall("hal"):
        if len(hals) >= MAX_HAL:
            raise ValueError("Too many HAL declarations")
        fmt = hal.get("format", "hidl")
        name = (hal.findtext("name") or "").strip()
        if fmt not in ("hidl", "aidl"):
            unsupported.append({"name": name, "reason": "format " + fmt})
            continue
        safe_name(name, PACKAGE)
        if hal.get("override") == "true":
            unsupported.append({"name": name, "reason": "override semantics not evaluated"})
        versions = strings(hal, "version")
        if fmt == "aidl" and not versions:
            versions = ["1"]
        if kind == "manifest" and any(a != b for a, b in
                                      (version_range(v, fmt) for v in versions)):
            raise ValueError("Manifest version must be concrete")
        ranges = [version_range(v, fmt) for v in versions]
        entries = []
        for interface in hal.findall("interface"):
            iface = safe_name((interface.findtext("name") or "").strip(), IFACE)
            if interface.findall("regex-instance"):
                unsupported.append({"name": name, "reason": "regex-instance not evaluated"})
            for instance in strings(interface, "instance"):
                entries.append((iface, safe_name(instance, INSTANCE), ranges))
        for fqname in strings(hal, "fqname"):
            if fmt == "hidl":
                m = re.fullmatch(r"@([0-9]+\.[0-9]+)::([^/]+)/([^/]+)", fqname)
                if not m:
                    raise ValueError("Invalid HIDL fqname")
                ver, iface, instance = m.groups()
                use = [version_range(ver, fmt)]
            else:
                m = re.fullmatch(r"([^/]+)/([^/]+)", fqname)
                if not m:
                    raise ValueError("Invalid AIDL fqname")
                iface, instance = m.groups()
                use = ranges
            entries.append((safe_name(iface, IFACE), safe_name(instance, INSTANCE), use))
        if not entries:
            entries.append((None, None, ranges))
        if any(not use for _, _, use in entries):
            unsupported.append({"name": name, "reason": "missing explicit version"})
        hals.append({"name": name, "format": fmt, "optional": hal.get("optional") == "true",
                     "entries": [{"interface": i, "instance": n, "ranges": v}
                                 for i, n, v in entries]})
    return {"source": source, "kind": kind, "type": side,
            "level": root.get("level"), "target_level": root.get("target-level"),
            "hals": hals, "unsupported": unsupported}


def files(root):
    paths = set()
    for partition in PARTITIONS:
        base = "/" + partition + "/etc/vintf"
        for fixed in ("manifest.xml", "compatibility_matrix.xml"):
            path = base + "/" + fixed
            try:
                guest_path(root, path)
            except FileNotFoundError:
                continue
            paths.add(path)
        for suffix in ("", "/manifest", "/compatibility_matrix"):
            directory = base + suffix
            try:
                actual = guest_path(root, directory)
            except FileNotFoundError:
                continue
            if not actual.is_dir():
                raise ValueError("Expected VINTF directory: " + directory)
            for p in actual.iterdir():
                if p.name.endswith(".xml") and (suffix or
                        p.name.startswith("compatibility_matrix.") or
                        p.name.startswith("manifest.")):
                    paths.add(directory + "/" + p.name)
                if len(paths) > MAX_FILES:
                    raise ValueError("Too many VINTF XML files")
    # Legacy layouts: record separately; do not apply merge precedence.
    for path in ("/vendor/manifest.xml", "/vendor/compatibility_matrix.xml",
                 "/system/manifest.xml", "/system/compatibility_matrix.xml"):
        try:
            guest_path(root, path)
        except FileNotFoundError:
            continue
        paths.add(path)
    if len(paths) > MAX_FILES:
        raise ValueError("Too many VINTF XML files")
    return sorted(paths)


def matches(required, offered):
    if required["interface"] is not None and required["interface"] != offered["interface"]:
        return False
    if required["instance"] is not None and required["instance"] != offered["instance"]:
        return False
    # Deliberately strict literal range, not libvintf minor-version semantics.
    return any(lo <= a <= hi and a == b
               for lo, hi in required["ranges"] for a, b in offered["ranges"])


def audit(root):
    documents, errors = [], []
    try:
        paths = files(root)
    except (OSError, ValueError) as exc:
        paths = []
        errors.append(str(exc))
    for path in paths:
        try:
            documents.append(parse_document(read_regular(guest_path(root, path), MAX_XML), path))
        except (OSError, ValueError, ET.ParseError) as exc:
            errors.append(path + ": " + str(exc))
    manifests = [d for d in documents if d["kind"] == "manifest"]
    matrices = [d for d in documents if d["kind"] == "compatibility-matrix"]
    comparisons = []
    for matrix in matrices:
        opposite = "device" if matrix["type"] == "framework" else "framework"
        providers = [d for d in manifests if d["type"] == opposite]
        for hal in matrix["hals"]:
            for entry in hal["entries"]:
                candidates = sorted({d["source"] for d in providers for h in d["hals"]
                                     if h["name"] == hal["name"] and h["format"] == hal["format"]
                                     for e in h["entries"] if matches(entry, e)})
                comparisons.append({"matrix": matrix["source"], "matrix_level": matrix["level"],
                                    "hal": hal["name"], "format": hal["format"],
                                    "optional": hal["optional"], "requirement": entry,
                                    "literal_candidates": candidates})
    missing = [c for c in comparisons if not c["optional"] and not c["literal_candidates"]]
    unsupported = [{"source": d["source"], **u} for d in documents for u in d["unsupported"]]
    complete_inputs = all(any(d["type"] == side and d["kind"] == kind for d in documents)
                          for side in ("framework", "device")
                          for kind in ("manifest", "compatibility-matrix"))
    return {"schema": "galwear-r800-vintf-inventory-v1",
            "status": "LITERAL_CANDIDATES_ONLY" if complete_inputs and comparisons and not
                       (missing or errors or unsupported) else "REVIEW_REQUIRED",
            "documents": documents, "comparisons": comparisons, "missing_required_candidates": missing,
            "unsupported": unsupported, "errors": errors, "all_document_types_present": complete_inputs,
            "fcm_level_selection_verified": False, "manifest_merge_verified": False,
            "libvintf_compatibility_verified": False, "hal_runtime_verified": False,
            "safe_to_flash": False}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--root", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    if a.output.resolve().is_relative_to(a.root.resolve()):
        p.error("Report must be outside guest root")
    out = audit(a.root)
    a.output.write_text(json.dumps(out, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(out["status"])
    return 0 if out["status"] == "LITERAL_CANDIDATES_ONLY" else 2


if __name__ == "__main__":
    raise SystemExit(main())
