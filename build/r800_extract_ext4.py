#!/usr/bin/env python3
"""Read selected donor files with debugfs, never mount or execute an image."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile

from r800_vendor_inputs import image_info, MAX_IMAGE
from r800_peripheral_firmware import REQUIRED, check_bytes

MAX_FILE = 64 * 1024**2
HCD = "BCM43012B0_002.001.021.0153.0156.hcd"
# Resolved regular glibc files rather than guest symlinks. Candidate locations
# are explicit; different donor layouts are reported missing, not guessed.
TIZEN = {
    "tizen/libc.so.6": ("/lib/libc-2.24.so", "/usr/lib/libc-2.24.so"),
    "tizen/libdl.so.2": ("/lib/libdl-2.24.so", "/usr/lib/libdl-2.24.so"),
    "tizen/libpthread.so.0": ("/lib/libpthread-2.24.so", "/usr/lib/libpthread-2.24.so"),
    "tizen/ld-linux.so.3": ("/lib/ld-2.24.so", "/usr/lib/ld-2.24.so"),
    "payload/fw/bt/" + HCD: ("/usr/lib/firmware/" + HCD,),
    "payload/fw/bcmdhd_sta.bin": ("/usr/lib/firmware/bcmdhd_sta.bin",),
    "payload/fw/nvram_net.txt": ("/usr/lib/firmware/nvram_net.txt",),
    "payload/fw/bcmdhd_clm.blob": ("/usr/lib/firmware/bcmdhd_clm.blob",),
}
TIZEN.update({"payload/"+name: ("/usr/lib/firmware/"+name.removeprefix("fw/"),)
              for name in REQUIRED})
VENDOR_NAMES = (
    "lib/libeffectsconfig.so",
    "bin/hw/android.hardware.sensors@1.0-service",
    "lib/hw/android.hardware.sensors@1.0-impl.so",
    "lib/android.hardware.sensors@1.0.so",
    "bin/hw/android.hardware.gnss@1.0-service",
    "lib/hw/android.hardware.gnss@1.0-impl.so",
    "lib/android.hardware.gnss@1.0.so",
    "etc/init/android.hardware.gnss@1.0-service.rc",
    "bin/hw/android.hardware.wifi@1.0-service",
    "etc/init/android.hardware.wifi@1.0-service.rc",
    "bin/hw/wpa_supplicant", "etc/init/wpa_supplicant.rc",
    "lib/android.hardware.wifi@1.0.so",
    "lib/android.hardware.wifi.supplicant@1.0.so",
)
TIZEN_GPS = {name: paths for name, paths in TIZEN.items() if name.startswith("tizen/")}
VENDOR_IDENTITY_FILES = ("build.prop", "default.prop", "etc/vintf/manifest.xml",
                         "bin/vndservicemanager") + VENDOR_NAMES
VENDOR_PROPERTIES = frozenset((
    "ro.product.vendor.brand", "ro.product.vendor.manufacturer",
    "ro.product.vendor.model", "ro.product.vendor.device", "ro.product.vendor.name",
    "ro.vendor.build.fingerprint", "ro.vendor.build.id", "ro.vendor.build.version.sdk",
    "ro.vendor.build.version.release", "ro.board.platform", "ro.product.cpu.abilist",
    "ro.product.vendor.cpu.abilist", "ro.vndk.version",
))
PROFILES = {"tizen": TIZEN, "tizen-gps": TIZEN_GPS,
            "vendor": {"vendor/"+n: ("/"+n,) for n in VENDOR_NAMES},
            "vendor-identity": {"vendor/"+n: ("/"+n,) for n in VENDOR_IDENTITY_FILES}}


# Match the 1.0 HIDL service contracts used by build_vendor.sh.
VINTF_REQUIRED = {
    "wifi": (("android.hardware.wifi", "IWifi"),
             ("android.hardware.wifi.supplicant", "ISupplicant")),
    "sensors": (("android.hardware.sensors", "ISensors"),),
    "gnss": (("android.hardware.gnss", "IGnss"),),
}


def vintf_inventory(path):
    """Inspect one bounded device manifest; no XML includes or external entities."""
    import xml.etree.ElementTree as ET
    from r800_android_userspace_preflight import read_regular
    try:
        raw = read_regular(path, 1024 * 1024)
        # Restrict to UTF-8 before parsing so alternate encodings cannot
        # bypass the DTD/entity prohibition.
        xml = raw.decode("utf-8-sig")
        if re.search(r"<!\s*(?:DOCTYPE|ENTITY)\b", xml, re.IGNORECASE):
            raise ValueError("DTD or entity declaration is not allowed")
        root = ET.fromstring(xml)
        if root.tag != "manifest" or root.get("type") != "device":
            raise ValueError("Expected device VINTF manifest")
        declarations = set()
        for hal in root.findall("hal"):
            if hal.get("format", "hidl") != "hidl" or hal.findtext("transport") != "hwbinder":
                continue
            name = (hal.findtext("name") or "").strip()
            for version in hal.findall("version"):
                if (version.text or "").strip() != "1.0":
                    continue
                for interface in hal.findall("interface"):
                    iface = (interface.findtext("name") or "").strip()
                    if any((i.text or "").strip() == "default" for i in interface.findall("instance")):
                        declarations.add((name, iface))
            for fqname in hal.findall("fqname"):
                match = re.fullmatch(r"@1\.0::([A-Za-z0-9_]+)/default", (fqname.text or "").strip())
                if match:
                    declarations.add((name, match[1]))
        missing = {group: [name + "@1.0::" + iface + "/default"
                           for name, iface in required if (name, iface) not in declarations]
                   for group, required in VINTF_REQUIRED.items()}
        return {"status": "DECLARATIONS_PRESENT" if not any(missing.values()) else "REVIEW_REQUIRED",
                "missing_by_group": missing, "compatibility_verified": False}
    except (OSError, ValueError, ET.ParseError) as exc:
        return {"status": "REVIEW_REQUIRED", "reason": str(exc),
                "compatibility_verified": False}


# This is an identification checklist, not a list of supported devices.
IDENTITY_REQUIRED = ("ro.product.vendor.model", "ro.product.vendor.device",
                     "ro.vendor.build.id", "ro.vendor.build.fingerprint")
FINGERPRINT = re.compile(
    r"(?P<brand>[^/:\s]+)/(?P<product>[^/:\s]+)/(?P<device>[^/:\s]+):"
    r"(?P<release>[^/:\s]+)/(?P<build_id>[^/:\s]+)/(?P<incremental>[^/:\s]+):"
    r"(?P<type>[^/:\s]+)/(?P<tags>[^/:\s]+)")


def identity_inventory(properties, conflicts):
    """Report observed identity completeness and contradictions only."""
    missing = [key for key in IDENTITY_REQUIRED if not properties.get(key)]
    problems = ["Conflicting property: " + key for key in sorted(set(conflicts))]
    fingerprint = properties.get("ro.vendor.build.fingerprint")
    fields = {}
    if fingerprint:
        match = FINGERPRINT.fullmatch(fingerprint)
        if not match:
            problems.append("Unrecognized fingerprint format")
        else:
            fields = match.groupdict()
            for field, key in (("brand", "ro.product.vendor.brand"),
                               ("device", "ro.product.vendor.device"),
                               ("build_id", "ro.vendor.build.id"),
                               ("release", "ro.vendor.build.version.release")):
                if key in properties and properties[key] != fields[field]:
                    problems.append("Fingerprint differs from " + key)
    sdk = properties.get("ro.vendor.build.version.sdk")
    if sdk is not None and not re.fullmatch(r"[1-9][0-9]{0,2}", sdk):
        problems.append("Unrecognized vendor SDK")
    return {"status": "IDENTITY_FIELDS_PRESENT" if not missing and not problems else "REVIEW_REQUIRED",
            "missing": missing, "problems": problems, "fingerprint_fields": fields,
            "identity_verified": False, "donor_authenticity_verified": False,
            "compatibility_verified": False, "safe_to_flash": False}


def hidl_dependency_inventory(elf, names):
    """Classify direct dependencies in the selected donor inventory only.

    /vendor/lib is the explicit candidate directory for ARM32 here.
    Never infer Android namespace resolution or treat lib/hw as a search path.
    """
    objects = sorted(n for n in names if n.startswith("vendor/bin/") or n.endswith(".so"))
    edges, review = [], []
    for name in objects:
        info = elf.get(name)
        if not info or info["status"] != "ARM32_DYNAMIC":
            review.append({"object": name, "reason": "Missing or invalid ELF"})
            continue
        if info["custom_search_path"]:
            review.append({"object": name, "reason": "RPATH/RUNPATH requires review"})
        for dep in sorted(info["needed"]):
            candidate = "vendor/lib/" + dep
            provider = elf.get(candidate)
            if provider is None:
                status = "OUTSIDE_SELECTED_INVENTORY"
            elif (provider["status"] != "ARM32_DYNAMIC" or
                  provider["elf_type"] != "ET_DYN" or
                  provider["soname"] not in (None, dep)):
                status = "CANDIDATE_REJECTED"
            elif candidate in names:
                status = "SAME_GROUP_CANDIDATE"
            else:
                status = "OTHER_GROUP_CANDIDATE"
            edges.append({"from": name, "needed": dep, "candidate": candidate,
                          "status": status})
    return {"status": "DIRECT_INVENTORY_ONLY" if not review and all(
                e["status"] == "SAME_GROUP_CANDIDATE" for e in edges) else "REVIEW_REQUIRED",
            "objects": objects, "edges": edges, "elf_review": review,
            "external_names": sorted({e["needed"] for e in edges
                                      if e["status"] == "OUTSIDE_SELECTED_INVENTORY"}),
            "dependency_closure_verified": False, "namespace_resolution_verified": False,
            "runtime_verified": False, "safe_to_flash": False}


def vendor_identity(tree, files):
    """Report observed identity and group completeness, not donor compatibility."""
    from r800_android_linker_audit import inspect
    properties = {}
    conflicts = []
    for name in ("vendor/build.prop", "vendor/default.prop"):
        if files[name]["status"] != "EXTRACTED":
            continue
        p = tree / name
        if p.stat().st_size > 1024 * 1024:
            raise ValueError("Vendor properties exceed byte budget")
        for line in p.read_text(encoding="utf-8").splitlines():
            key, sep, value = line.partition("=")
            key, value = key.strip(), value.strip()
            if not sep or key not in VENDOR_PROPERTIES:
                continue
            if not value or len(value) > 512 or not value.isprintable():
                raise ValueError("Invalid vendor property: " + key)
            if key in properties and properties[key] != value:
                conflicts.append(key)
            else:
                properties[key] = value
    elf = {}
    for name, row in files.items():
        if not (name.endswith(".so") or name.startswith("vendor/bin/")):
            continue
        if row["status"] != "EXTRACTED":
            continue
        try:
            info = inspect((tree / name).read_bytes())
            elf[name] = {"status": "ARM32_DYNAMIC" if info["abi"] == "arm" and
                         info["has_dynamic"] and (not name.endswith(".so") or
                         info["elf_type"] == "ET_DYN") else "REVIEW_REQUIRED",
                         "abi": info["abi"], "elf_type": info["elf_type"],
                         "needed": info["needed"], "soname": info["soname"],
                         "custom_search_path": info["custom_search_path"]}
        except (ValueError, KeyError) as exc:
            elf[name] = {"status": "REJECTED", "reason": str(exc)}
    groups = {}
    for group in ("wifi", "sensors", "gnss"):
        names = ["vendor/"+n for n in VENDOR_NAMES if
                 ("hardware."+group+"@" in n or
                  (group == "wifi" and ("wpa_supplicant" in n or "hardware.wifi.supplicant@" in n)))]
        missing = [n for n in names if files[n]["status"] != "EXTRACTED"]
        invalid = [n for n in names if n in elf and elf[n]["status"] != "ARM32_DYNAMIC"]
        groups[group] = {"missing": missing, "elf_review": invalid,
                         "inventory_complete": not missing and not invalid,
                         "direct_dependencies": hidl_dependency_inventory(elf, names)}
    manifest = "vendor/etc/vintf/manifest.xml"
    vintf = vintf_inventory(tree / manifest) if files[manifest]["status"] == "EXTRACTED" else {
        "status": "REVIEW_REQUIRED", "reason": "Missing device manifest",
        "compatibility_verified": False}
    return {"properties": properties, "property_conflicts": sorted(set(conflicts)),
            "identity_inventory": identity_inventory(properties, conflicts),
            "vintf": vintf,
            "elf": elf, "hidl_groups": groups,
            "vintf_manifest_present": files["vendor/etc/vintf/manifest.xml"]["status"] == "EXTRACTED",
            "identity_verified": False, "dependency_closure_verified": False,
            "runtime_verified": False, "safe_to_flash": False}



def command(tool, image, request, cwd=None):
    # debugfs opens read-only by default. No -w, no shell, no guest execution.
    env = dict(os.environ, LC_ALL="C")
    return subprocess.run([tool, "-R", request, str(image)], cwd=cwd,
                          env=env, capture_output=True, text=True, timeout=60,
                          check=True)


def locate(tool, image, guest, limit=MAX_FILE):
    if not re.fullmatch(r"/[A-Za-z0-9_./@+-]+", guest) or ".." in guest.split("/"):
        raise ValueError("Invalid guest path")
    result = command(tool, image, "stat " + guest)
    if "File not found" in result.stderr:
        return None
    match = re.search(r"Inode:\s+(\d+)\s+Type:\s+(\w+)", result.stdout)
    size = re.search(r"\bSize:\s+(\d+)", result.stdout)
    if not match or not size or match[2] != "regular":
        raise ValueError("Expected regular donor file: " + guest)
    length = int(size[1])
    if not 0 < length <= limit:
        raise ValueError("Donor file size out of bounds: " + guest)
    return int(match[1]), length


MAX_WALK_OBJECTS = 128
MAX_WALK_BYTES = 128 * 1024**2
MAX_WALK_DEPTH = 16
MAX_WALK_EDGES = 4096


class DonorSymbolInventory:
    """Bounded transient ELF symbol metadata; never publish raw library bytes."""

    def __init__(self):
        self.objects = {}
        self.records = 0
        self.name_bytes = 0
        self.exhausted = False

    def add(self, path, info):
        keys = ("abi", "has_dynamic", "dynamic_symbol_count", "symbol_imports",
                "symbol_exports", "unsupported_symbols", "version_needs",
                "version_definitions")
        if self.exhausted or any(key not in info for key in keys):
            return
        symbols = info["symbol_imports"] + info["symbol_exports"] + info["unsupported_symbols"]
        count = len(symbols)
        size = sum(len(v["name"].encode("utf-8", "surrogateescape")) for v in symbols)
        if self.records + count > 32768 or self.name_bytes + size > 4 * 1024**2:
            self.exhausted = True
            return
        self.records += count
        self.name_bytes += size
        self.objects[path] = {key: info[key] for key in keys}


def donor_namespace_candidates(config_path, expected_sha, vendor, system):
    """Compare inspected graph edges with a caller-supplied linker config.

    No filesystem search or precedence inference; uninspected alternatives,
    isolation realpaths, global groups and generated config provenance remain open.
    """
    from collections import deque
    from r800_android_userspace_preflight import read_regular
    from r800_linker_namespaces import parse, section_for, MAX_CONFIG
    raw = read_regular(Path(config_path), MAX_CONFIG)
    if hashlib.sha256(raw).hexdigest() != expected_sha:
        raise ValueError("Linker config SHA-256 mismatch")
    report = {"status": "REVIEW_REQUIRED", "config_sha256": expected_sha,
              "config_origin": "CALLER_SUPPLIED", "roots": [], "checks": [], "errors": [],
              "runtime_resolution_verified": False, "config_provenance_verified": False,
              "safe_to_flash": False}
    try:
        parsed = parse(raw.decode("utf-8"), "arm")
    except ValueError as exc:
        report["errors"].append(str(exc))
        return report
    if parsed["unsupported_properties"]:
        report["errors"].append("Unsupported linker configuration properties")
        report["unsupported_properties"] = parsed["unsupported_properties"]
        return report
    objects, edges, system_paths = {}, {}, {}
    for path, row in vendor["objects"].items():
        if row["status"] == "CANDIDATE_ONLY":
            guest = "/" + path
            objects[path] = guest
            edges[path] = {dep: None for dep in row["needed"]}
    for name, row in system.get("system_candidate_graph", {}).items():
        if row["status"] != "CANDIDATE_ONLY":
            continue
        c = row["candidates"][0]
        key = c["origin"] + ":" + c["path"]
        guest = c["path"]
        if c["origin"] == "system":
            guest = guest if guest.startswith("/system/") else "/system" + guest
        else:
            guest = "/apex/" + c["origin"] + guest
        system_paths[name] = key
        objects[key] = guest
        edges[key] = {dep: None for dep in c["needed"]}
    for edge in vendor["edges"]:
        if edge["from"] not in edges:
            continue
        if edge["status"] == "CANDIDATE_ONLY" and edge["candidate"] in objects:
            edges[edge["from"]][edge["needed"]] = edge["candidate"]
        elif edge["status"] == "OUTSIDE_VENDOR_LIB":
            edges[edge["from"]][edge["needed"]] = system_paths.get(edge["needed"])
    for edge in system.get("system_dependency_edges", []):
        if edge["from"] in system_paths:
            edges[system_paths[edge["from"]]][edge["needed"]] = system_paths.get(edge["needed"])
    pending, visited = deque(), set()
    for root in vendor["roots"]:
        if not root.startswith("vendor/bin/"):
            continue
        section = section_for(parsed, "/" + root)
        report["roots"].append({"path": "/" + root, "section": section})
        if section is None or root not in objects:
            report["errors"].append("Unmapped or uninspected root: " + root)
        else:
            pending.append((section, "default", root))
    while pending:
        section, ns_name, path = pending.popleft()
        state = (section, ns_name, path)
        if state in visited:
            continue
        if len(visited) >= 1024:
            report["errors"].append("Namespace state budget exceeded")
            break
        visited.add(state)
        spaces = parsed["sections"][section]
        ns = spaces[ns_name]
        for dep, candidate in edges[path].items():
            if len(report["checks"]) >= MAX_WALK_EDGES:
                report["errors"].append("Namespace edge budget exceeded")
                return report
            allowed, denied = [ns_name], []
            for dest in ns["links"]:
                policy = ns["link_policies"].get(dest, {})
                if policy.get("allow_all_shared_libs") or dep in policy.get("shared_libs", []):
                    allowed.append(dest)
                else:
                    denied.append(dest)
            matches = []
            guest = objects.get(candidate)
            if guest is not None:
                for dest in allowed:
                    if guest in [p.rstrip("/") + "/" + dep for p in spaces[dest]["search_paths"]]:
                        matches.append(dest)
            report["checks"].append({"from": objects[path], "namespace": ns_name,
                "section": section, "needed": dep, "candidate": guest,
                "matching_namespaces": matches, "denied_links": denied,
                "status": "CONFIG_PATH_MATCH_ONLY" if len(matches) == 1 else "REVIEW_REQUIRED"})
            if len(matches) == 1:
                pending.append((section, matches[0], candidate))
    if (report["roots"] and report["checks"] and not report["errors"]
            and not vendor["budget_exhausted"] and not vendor["problems"]
            and (vendor["status"] == "VENDOR_LIB_CANDIDATES_ONLY" or
                 system.get("status") == "SYSTEM_PATH_CANDIDATES_ONLY")
            and all(row["status"] == "CONFIG_PATH_MATCH_ONLY" for row in report["checks"])):
        report["status"] = "CONFIG_PATH_MATCHES_ONLY"
    return report


def donor_symbol_candidates(inventory, vendor, system):
    """Compare potential providers in the selected graph, not linker lookup order."""
    from r800_android_linker_audit import symbol_candidates
    selected, edges = {}, {}
    for path, row in vendor["objects"].items():
        if row["status"] == "CANDIDATE_ONLY":
            selected[path] = inventory.objects.get(path)
            edges[path] = {dep: [] for dep in row["needed"]}
    system_paths = {}
    for name, row in system.get("system_candidate_graph", {}).items():
        if row["status"] != "CANDIDATE_ONLY":
            continue
        candidate = row["candidates"][0]
        path = candidate["origin"] + ":" + candidate["path"]
        system_paths[name] = path
        selected[path] = inventory.objects.get(path)
        edges[path] = {dep: [] for dep in candidate["needed"]}
    for edge in vendor["edges"]:
        path = edge["from"]
        if path not in edges:
            continue
        candidate = edge["candidate"]
        if edge["status"] == "CANDIDATE_ONLY" and candidate in selected:
            edges[path][edge["needed"]] = [candidate]
        elif edge["status"] == "OUTSIDE_VENDOR_LIB" and edge["needed"] in system_paths:
            edges[path][edge["needed"]] = [system_paths[edge["needed"]]]
    for edge in system.get("system_dependency_edges", []):
        if edge["from"] in system_paths and edge["needed"] in system_paths:
            edges[system_paths[edge["from"]]][edge["needed"]] = [system_paths[edge["needed"]]]
    missing_metadata = sorted(path for path, info in selected.items()
                              if info is None or info["dynamic_symbol_count"] is None)
    unsupported = sorted(path for path, info in selected.items()
                         if info is not None and info["unsupported_symbols"])
    version_review = []
    for path, info in selected.items():
        if info is None:
            continue
        for need in info["version_needs"]:
            providers = edges[path].get(need["library"], [])
            if len(providers) != 1 or selected.get(providers[0]) is None:
                version_review.append({"from": path, **need, "reason": "Provider not inspected"})
                continue
            definitions = selected[providers[0]]["version_definitions"]
            if need["version"] not in {v["version"] for v in definitions if not v["base"]}:
                version_review.append({"from": path, **need, "reason": "Version definition not found"})
    result = symbol_candidates(selected, edges)
    unresolved_edges = sum(not providers for deps in edges.values() for providers in deps.values())
    graph_complete = (bool(selected) and not vendor["budget_exhausted"] and not vendor["problems"]
                      and (vendor["status"] == "VENDOR_LIB_CANDIDATES_ONLY" or
                           system.get("status") == "SYSTEM_PATH_CANDIDATES_ONLY"))
    review = (not graph_complete or inventory.exhausted or missing_metadata or unsupported or
              version_review or unresolved_edges or result["limit_exceeded"] or
              any(result[key] for key in ("missing_strong", "ambiguous", "incomplete")))
    return {"status": "SYMBOL_CANDIDATES_ONLY" if not review else "REVIEW_REQUIRED",
            "objects": sorted(selected), "missing_metadata": missing_metadata,
            "unsupported_symbol_objects": unsupported, "version_review": version_review,
            "unresolved_edges": unresolved_edges, "symbol_candidates": result,
            "inventory_budget_exhausted": inventory.exhausted,
            "inventory_records": inventory.records, "inventory_name_bytes": inventory.name_bytes,
            "symbol_resolution_verified": False, "namespace_resolution_verified": False,
            "runtime_verified": False, "safe_to_flash": False}


def vendor_dependency_walk(tool, snapshot, scratch, tree, files, symbols=None):
    """Bounded ARM32 vendor/lib candidate graph, not Android resolution.

    Read only from the same verified snapshot, retain only metadata for
    additional dependencies. Missing providers may be in system/VNDK.
    """
    from collections import deque
    from r800_android_linker_audit import inspect
    roots = sorted(name for name, row in files.items()
                   if row["status"] == "EXTRACTED" and
                   (name.startswith("vendor/bin/") or name.endswith(".so")))
    pending = deque((name, 0) for name in roots)
    objects, edges, problems = {}, [], []
    total = 0
    exhausted = False
    while pending:
        name, depth = pending.popleft()
        if name in objects:
            continue
        if len(objects) >= MAX_WALK_OBJECTS or depth > MAX_WALK_DEPTH:
            problems.append("Object or depth budget exceeded")
            exhausted = True
            break
        objects[name] = {"status": "REVIEW_REQUIRED"}
        try:
            if name in files and files[name]["status"] == "EXTRACTED":
                raw = (tree / name).read_bytes()
                if hashlib.sha256(raw).hexdigest() != files[name]["sha256"]:
                    raise ValueError("Selected member digest mismatch")
                if total + len(raw) > MAX_WALK_BYTES:
                    exhausted = True
                    raise ValueError("Byte budget exceeded")
            else:
                found = locate(tool, snapshot, "/" + name.removeprefix("vendor/"))
                if found is None:
                    objects[name] = {"status": "OUTSIDE_VENDOR_LIB"}
                    continue
                inode, length = found
                if total + length > MAX_WALK_BYTES:
                    exhausted = True
                    raise ValueError("Byte budget exceeded")
                target = scratch / "dependency-member"
                try:
                    command(tool, snapshot, "dump <%d> dependency-member" % inode, cwd=scratch)
                    st = target.lstat()
                    if not stat.S_ISREG(st.st_mode) or st.st_size != length:
                        raise ValueError("Dependency size mismatch")
                    raw = target.read_bytes()
                finally:
                    target.unlink(missing_ok=True)
            total += len(raw)
            info = inspect(raw)
            if info["abi"] != "arm" or not info["has_dynamic"]:
                raise ValueError("Expected dynamic ARM32 ELF")
            if name.endswith(".so") and (info["elf_type"] != "ET_DYN" or
                    info["soname"] not in (None, name.rsplit("/", 1)[-1])):
                raise ValueError("Invalid shared object type or SONAME")
            if info["custom_search_path"]:
                raise ValueError("RPATH/RUNPATH requires review")
            if symbols is not None:
                symbols.add(name, info)
            objects[name] = {"status": "CANDIDATE_ONLY", "sha256": hashlib.sha256(raw).hexdigest(),
                             "bytes": len(raw), "needed": info["needed"], "depth": depth}
            for dep in sorted(info["needed"]):
                if len(edges) >= MAX_WALK_EDGES:
                    exhausted = True
                    raise ValueError("Edge budget exceeded")
                if not re.fullmatch(r"[A-Za-z0-9_@.+~-]{1,255}", dep) or dep in (".", ".."):
                    raise ValueError("Invalid DT_NEEDED basename")
                candidate = "vendor/lib/" + dep
                edges.append({"from": name, "needed": dep, "candidate": candidate})
                pending.append((candidate, depth + 1))
        except (OSError, ValueError, KeyError, subprocess.SubprocessError) as exc:
            objects[name] = {"status": "REVIEW_REQUIRED", "reason": str(exc)}
            problems.append(name + ": " + str(exc))
            if exhausted:
                break
    for edge in edges:
        edge["status"] = objects.get(edge["candidate"], {}).get("status", "NOT_INSPECTED")
    external = sorted({e["needed"] for e in edges if e["status"] == "OUTSIDE_VENDOR_LIB"})
    return {"status": "VENDOR_LIB_CANDIDATES_ONLY" if roots and not problems and not external and
            all(o["status"] == "CANDIDATE_ONLY" for o in objects.values()) else "REVIEW_REQUIRED",
            "roots": roots, "objects": objects, "edges": edges, "external_names": external,
            "problems": problems, "budget_exhausted": exhausted, "bytes_inspected": total,
            "dependency_closure_verified": False, "namespace_resolution_verified": False,
            "runtime_verified": False, "safe_to_flash": False}


def snapshot_image(image, snapshot, expected_sha):
    """Copy bounded bytes once; debugfs never reopens the mutable donor path."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
    initial = image.lstat()
    if not stat.S_ISREG(initial.st_mode) or not 0 < initial.st_size <= MAX_IMAGE:
        raise ValueError("Expected bounded regular donor image")

    def identity(s):
        return (s.st_dev, s.st_ino, s.st_mode, s.st_size,
                s.st_mtime_ns, s.st_ctime_ns)

    digest = hashlib.sha256()
    count = 0
    with os.fdopen(os.open(image, flags), "rb") as src:
        if identity(os.fstat(src.fileno())) != identity(initial):
            raise ValueError("Donor changed before snapshot")
        with snapshot.open("xb") as dst:
            for block in iter(lambda: src.read(1024 * 1024), b""):
                count += len(block)
                if count > initial.st_size:
                    raise ValueError("Donor size changed")
                digest.update(block)
                dst.write(block)
        if identity(os.fstat(src.fileno())) != identity(initial):
            raise ValueError("Donor changed during snapshot")
    if count != initial.st_size or identity(image.lstat()) != identity(initial):
        raise ValueError("Donor changed during snapshot")
    if digest.hexdigest() != expected_sha:
        raise ValueError("Input image SHA-256 mismatch")
    snapshot.chmod(0o400)
    return identity(initial)


def selected_apex_payloads(tool, snapshot, scratch, vndk):
    """Read fixed APEX archive locations; never activate or mount payloads."""
    import zipfile
    from r800_android_runtime_extract import extract_payload, MAX_APEX
    packages = {"com.android.runtime": ("/lib/bionic", "/lib")}
    if vndk and re.fullmatch(r"[1-9][0-9]{0,2}", vndk):
        packages["com.android.vndk.v" + vndk] = ("/lib",)
    inventory, locations = {}, []
    for index, (package, directories) in enumerate(packages.items()):
        paths = [prefix + "/" + package + ".apex" for prefix in ("/apex", "/system/apex")]
        row = {"status": "NOT_FOUND_IN_SELECTED_PATHS", "paths": paths}
        inventory[package] = row
        try:
            found = [(path, locate(tool, snapshot, path, MAX_APEX)) for path in paths]
            found = [(path, item) for path, item in found if item is not None]
            if not found:
                continue
            if len(found) != 1:
                row["status"] = "AMBIGUOUS"
                continue
            path, (inode, length) = found[0]
            archive = scratch / ("apex-%d.zip" % index)
            payload = scratch / ("apex-%d.img" % index)
            command(tool, snapshot, "dump <%d> %s" % (inode, archive.name), cwd=scratch)
            st = archive.lstat()
            if not stat.S_ISREG(st.st_mode) or st.st_size != length:
                raise ValueError("APEX archive size mismatch")
            from r800_android_runtime_extract import digest
            archive_sha = digest(archive, MAX_APEX)
            extract_payload(archive, payload)
            payload.chmod(0o400)
            metadata = image_info(payload)
            row.update({"status": "PAYLOAD_CANDIDATE_ONLY", "source": path,
                        "archive_sha256": archive_sha, "payload_sha256": metadata["sha256"],
                        "payload_bytes": metadata["bytes"]})
            locations.extend((package, payload, directory) for directory in directories)
        except (OSError, ValueError, zipfile.BadZipFile, subprocess.SubprocessError) as exc:
            row.update({"status": "REVIEW_REQUIRED", "reason": str(exc)})
    return inventory, locations


def selected_selinux_inventory(tool, snapshot, scratch, partition):
    """Read fixed SELinux files from one verified donor snapshot, metadata only."""
    from r800_selinux_inventory import policy_header, contexts, MAX_POLICY, MAX_TEXT, CONTEXT, VERSION
    base = "/etc/selinux/"
    prefixes = ("", "/system") if partition == "system" else ("", "/vendor")
    suffix = "plat_sepolicy_and_mapping.sha256"
    if partition == "vendor":
        wanted = {"precompiled_sepolicy": "policy", "precompiled_sepolicy." + suffix: "id",
                  "plat_sepolicy_vers.txt": "version", "vendor_sepolicy.cil": "cil",
                  "vendor_file_contexts": "file_contexts",
                  "vendor_hwservice_contexts": "hwservice_contexts"}
    else:
        wanted = {suffix: "id", "plat_sepolicy.cil": "cil",
                  "plat_file_contexts": "file_contexts", "plat_hwservice_contexts": "hwservice_contexts"}
    files = {}
    for name, kind in wanted.items():
        paths = [prefix + base + name for prefix in prefixes]
        row = {"status": "MISSING"}
        files[name] = row
        try:
            limit = MAX_POLICY if kind == "policy" else MAX_TEXT
            if kind in ("id", "version"):
                limit = 256
            found = [(path, locate(tool, snapshot, path, limit)) for path in paths]
            found = [(path, item) for path, item in found if item is not None]
            if not found:
                continue
            if len(found) != 1:
                row.update(status="AMBIGUOUS", paths=[path for path, _ in found])
                continue
            path, (inode, length) = found[0]
            target = scratch / "selinux-member"
            try:
                command(tool, snapshot, "dump <%d> selinux-member" % inode, cwd=scratch)
                st = target.lstat()
                if not stat.S_ISREG(st.st_mode) or st.st_size != length:
                    raise ValueError("SELinux member size mismatch")
                raw = target.read_bytes()
            finally:
                target.unlink(missing_ok=True)
            row.update(path=path, sha256=hashlib.sha256(raw).hexdigest(), bytes=len(raw))
            if kind == "policy":
                row["header"] = policy_header(raw)
                if not 19 <= row["header"]["version"] <= 31 or not row["header"]["config_bits"] & 1:
                    raise ValueError("Policy outside target MLS version range 19..31")
            elif kind == "id":
                value = raw.decode("ascii").strip()
                if not re.fullmatch(r"[a-f0-9]{64}", value):
                    raise ValueError("Invalid partition policy identifier")
                row["identifier"] = value
            elif kind == "version":
                value = raw.decode("ascii").strip()
                if not VERSION.fullmatch(value):
                    raise ValueError("Invalid policy version marker")
                row["version"] = value
            elif kind.endswith("_contexts"):
                row["inventory"] = contexts(raw, kind)
                if row["inventory"]["duplicates"] or row["inventory"]["unsupported_lines"]:
                    raise ValueError("Context inventory requires review")
                if kind == "hwservice_contexts":
                    labels = {}
                    for line in raw.decode("utf-8").splitlines():
                        fields = line.split()
                        if fields and not line.lstrip().startswith("#"):
                            values = [field for field in fields[1:] if CONTEXT.fullmatch(field)]
                            if len(values) == 1:
                                labels[fields[0]] = values[0]
                    row["labels"] = labels
            else:
                row["cil_compiled"] = False
            row["status"] = "INVENTORIED"
        except (OSError, ValueError, KeyError, subprocess.SubprocessError) as exc:
            row.update(status="REVIEW_REQUIRED", reason=str(exc))
    return {"files": files, "policy_loaded": False, "safe_to_flash": False}


def donor_selinux_comparison(vendor, system):
    suffix = "plat_sepolicy_and_mapping.sha256"
    vf, sf = vendor["files"], system.get("files", {})
    actual = sf.get(suffix, {})
    expected = vf.get("precompiled_sepolicy." + suffix, {})
    ids_match = (actual.get("status") == expected.get("status") == "INVENTORIED" and
                 actual.get("identifier") == expected.get("identifier"))
    service_labels = {}
    conflicts = []
    for files, name in ((sf, "plat_hwservice_contexts"), (vf, "vendor_hwservice_contexts")):
        row = files.get(name, {})
        if row.get("status") != "INVENTORIED":
            continue
        for service, label in row["labels"].items():
            if service in service_labels and service_labels[service] != label:
                conflicts.append(service)
            service_labels[service] = label
    required = sorted(package + "::" + interface
                      for pairs in VINTF_REQUIRED.values() for package, interface in pairs)
    missing = [name for name in required if name not in service_labels]
    complete = (ids_match and not missing and not conflicts and
                vf.get("precompiled_sepolicy", {}).get("status") == "INVENTORIED" and
                all(row["status"] == "INVENTORIED" for row in list(vf.values()) + list(sf.values())))
    return {"status": "SELECTED_SELINUX_METADATA_ONLY" if complete else "REVIEW_REQUIRED",
            "platform_policy_ids_match": ids_match, "required_hwservice_labels": required,
            "missing_hwservice_labels": missing, "conflicting_hwservice_labels": sorted(set(conflicts)),
            "selected_hwservice_labels": {k: service_labels[k] for k in required if k in service_labels},
            "policy_compiled_verified": False, "policy_loaded_verified": False,
            "neverallow_verified": False, "domain_transitions_verified": False,
            "runtime_enforcing_verified": False, "safe_to_flash": False}


def system_dependency_candidates(tool, image, expected_sha, scratch, walk, properties, include_apex=False, symbols=None, include_selinux=False):
    """Probe explicit raw EXT4 system paths for vendor external names.

    No APEX activation, symlink resolution, namespace ordering or guest execution.
    """
    from collections import deque
    from r800_android_linker_audit import inspect
    image = Path(image).absolute()
    snapshot = scratch / "system.img"
    identity = snapshot_image(image, snapshot, expected_sha)
    before = image_info(snapshot)
    if before["sha256"] != expected_sha:
        raise ValueError("System snapshot SHA-256 mismatch")
    vndk = properties.get("ro.vndk.version")
    dirs = ["/lib", "/system/lib"]
    if vndk and re.fullmatch(r"[1-9][0-9]{0,2}", vndk):
        dirs += [base + "/" + sub + "-" + vndk
                 for base in ("/lib", "/system/lib") for sub in ("vndk", "vndk-sp")]
    apex_inventory, apex_locations = selected_apex_payloads(tool, snapshot, scratch, vndk) if include_apex else ({}, [])
    search_locations = [("system", snapshot, directory) for directory in dirs] + apex_locations
    results = {}
    edges = []
    roots = sorted(set(walk['external_names']))
    pending = deque((name, 0) for name in roots)
    queued = set(roots)
    total = 0
    probes = 0
    exhausted = False
    while pending:
        name, depth = pending.popleft()
        if len(results) >= MAX_WALK_OBJECTS or depth > MAX_WALK_DEPTH:
            exhausted = True
            break
        if not re.fullmatch(r"[A-Za-z0-9_@.+~-]{1,255}", name) or name in (".", ".."):
            raise ValueError("Invalid system dependency basename")
        candidates = []
        problems = []
        for origin, filesystem, directory in search_locations:
            guest = directory + "/" + name
            if probes >= MAX_WALK_EDGES or total >= MAX_WALK_BYTES:
                exhausted = True
                break
            probes += 1
            try:
                found = locate(tool, filesystem, guest)
                if found is None:
                    continue
                inode, length = found
                if total + length > MAX_WALK_BYTES:
                    exhausted = True
                    break
                total += length
                target = scratch / "system-member"
                try:
                    command(tool, filesystem, "dump <%d> system-member" % inode, cwd=scratch)
                    st = target.lstat()
                    if not stat.S_ISREG(st.st_mode) or st.st_size != length:
                        raise ValueError("System dependency size mismatch")
                    raw = target.read_bytes()
                finally:
                    target.unlink(missing_ok=True)
                info = inspect(raw)
                if (info["abi"] != "arm" or info["elf_type"] != "ET_DYN" or
                        not info["has_dynamic"] or info["soname"] not in (None, name) or
                        info["custom_search_path"]):
                    raise ValueError("System candidate ELF/SONAME/search path requires review")
                if symbols is not None:
                    symbols.add(origin + ":" + guest, info)
                candidates.append({"path": guest, "origin": origin, "sha256": hashlib.sha256(raw).hexdigest(),
                                   "bytes": len(raw), "needed": info["needed"]})
            except (OSError, ValueError, KeyError, subprocess.SubprocessError) as exc:
                problems.append({"path": guest, "origin": origin, "reason": str(exc)})
        status = ("REVIEW_REQUIRED" if exhausted or problems else
                  "NOT_FOUND_IN_SELECTED_PATHS" if not candidates else
                  "AMBIGUOUS" if len(candidates) > 1 else "CANDIDATE_ONLY")
        results[name] = {"status": status, "candidates": candidates, "problems": problems,
                         "depth": depth}
        if status == "CANDIDATE_ONLY":
            for dep in sorted(set(candidates[0]["needed"])):
                if not re.fullmatch(r"[A-Za-z0-9_@.+~-]{1,255}", dep) or dep in (".", ".."):
                    problems.append({"path": candidates[0]["path"], "reason": "Invalid DT_NEEDED basename"})
                    results[name]["status"] = "REVIEW_REQUIRED"
                    continue
                if len(edges) >= MAX_WALK_EDGES:
                    exhausted = True
                    break
                edges.append({"from": name, "needed": dep})
                if dep not in queued:
                    if len(queued) >= MAX_WALK_OBJECTS:
                        exhausted = True
                        break
                    queued.add(dep)
                    pending.append((dep, depth + 1))
        if exhausted:
            break
    for edge in edges:
        edge["status"] = results.get(edge["needed"], {}).get("status", "NOT_INSPECTED")
    selinux = selected_selinux_inventory(tool, snapshot, scratch, "system") if include_selinux else {}
    current = image.lstat()
    if (current.st_dev, current.st_ino, current.st_mode, current.st_size,
            current.st_mtime_ns, current.st_ctime_ns) != identity:
        raise ValueError("System donor image changed")
    if image_info(snapshot) != before:
        raise ValueError("System snapshot changed")
    for package, payload, _ in apex_locations:
        if image_info(payload)["sha256"] != apex_inventory[package]["payload_sha256"]:
            raise ValueError("APEX payload changed during inspection")
    complete = (bool(walk["roots"]) and not exhausted and not walk["budget_exhausted"]
                and all(row["status"] == "PAYLOAD_CANDIDATE_ONLY" for row in apex_inventory.values())
                and not walk["problems"] and set(results) == queued and
                all(row["status"] == "CANDIDATE_ONLY" for row in results.values()))
    return {"status": "SYSTEM_PATH_CANDIDATES_ONLY" if complete else "REVIEW_REQUIRED",
            "system_image_sha256": expected_sha, "snapshot_verified": True,
            "search_paths": dirs, "observed_vndk_version": vndk,
            "external_candidates": {name: results[name] for name in roots if name in results},
            "system_candidate_graph": results, "system_dependency_edges": edges,
            "uninspected_names": sorted(queued - set(results)),
            "budget_exhausted": exhausted,
            "bytes_inspected": total, "apex_inspected": bool(apex_locations),
            "apex_requested": include_apex, "apex_inventory": apex_inventory,
            "selinux_inventory": selinux,
            "apex_signature_verified": False, "apex_activation_verified": False,
            "dependency_closure_verified": False, "namespace_resolution_verified": False,
            "runtime_verified": False, "safe_to_flash": False}


def extract(image, output, profile, expected_sha, system_image=None, system_sha=None, include_apex=False,
            linker_config=None, linker_config_sha=None, include_selinux=False):
    image, output = Path(image).absolute(), Path(output).absolute()
    if profile not in PROFILES or not re.fullmatch(r"[0-9a-f]{64}", expected_sha):
        raise ValueError("Expected donor profile and SHA-256")
    if ((system_image is None) != (system_sha is None) or
            (system_image is not None and (profile != "vendor-identity" or
             not re.fullmatch(r"[0-9a-f]{64}", system_sha)))):
        raise ValueError("System image and SHA-256 require vendor-identity profile")
    if ((linker_config is None) != (linker_config_sha is None) or
            (linker_config is not None and (profile != "vendor-identity" or
             not re.fullmatch(r"[0-9a-f]{64}", linker_config_sha)))):
        raise ValueError("Linker config and SHA-256 require vendor-identity profile")
    if include_selinux and profile != "vendor-identity":
        raise ValueError("SELinux inventory requires vendor-identity profile")
    if include_apex and system_image is None:
        raise ValueError("APEX inspection requires system image")
    if output.exists() or output.is_symlink():
        raise ValueError("Output already exists")
    tool = shutil.which("debugfs")
    if not tool:
        raise ValueError("Install e2fsprogs (debugfs)")
    with tempfile.TemporaryDirectory(dir=output.parent) as tmp:
        scratch = Path(tmp)
        snapshot = scratch/"donor.img"
        source_identity = snapshot_image(image, snapshot, expected_sha)
        before = image_info(snapshot)
        if before["sha256"] != expected_sha:
            raise ValueError("Snapshot SHA-256 mismatch")
        tree = scratch/"files"
        tree.mkdir()
        files = {}
        for dest, candidates in PROFILES[profile].items():
            matches = []
            for guest in candidates:
                found = locate(tool, snapshot, guest)
                if found is not None:
                    matches.append((guest, found))
            if not matches:
                files[dest] = {"status": "MISSING", "candidates": list(candidates)}
                continue
            if len({m[1][0] for m in matches}) > 1:
                files[dest] = {"status": "AMBIGUOUS", "candidates": [m[0] for m in matches]}
                continue
            guest, (inode, length) = matches[0]
            target = scratch/"member"
            command(tool, snapshot, "dump <%d> member" % inode, cwd=scratch)
            st = target.lstat()
            if not stat.S_ISREG(st.st_mode) or st.st_size != length:
                raise ValueError("Extracted donor size mismatch: " + guest)
            raw = target.read_bytes()
            if dest.removeprefix("payload/") in REQUIRED:
                check_bytes(dest.removeprefix("payload/"), raw)
            destpath = tree/dest
            destpath.parent.mkdir(parents=True, exist_ok=True)
            os.rename(target, destpath)
            destpath.chmod(0o644)
            files[dest] = {"status":"EXTRACTED", "source":guest,
                           "bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest()}
        dependency_walk = None
        symbols = DonorSymbolInventory()
        if profile == "vendor-identity":
            dependency_walk = vendor_dependency_walk(tool, snapshot, scratch, tree, files, symbols)
        identity_report = None
        if profile == "vendor-identity":
            identity_report = vendor_identity(tree, files)
            if system_image is not None:
                identity_report["system_dependency_candidates"] = system_dependency_candidates(
                    tool, system_image, system_sha, scratch, dependency_walk, identity_report["properties"], include_apex, symbols, include_selinux)
            if include_selinux:
                vendor_policy = selected_selinux_inventory(tool, snapshot, scratch, "vendor")
                system_policy = identity_report.get("system_dependency_candidates", {}).get("selinux_inventory", {})
                identity_report["selinux_inventory"] = {"vendor": vendor_policy, "system": system_policy,
                    "comparison": donor_selinux_comparison(vendor_policy, system_policy)}
            identity_report["symbol_candidate_audit"] = donor_symbol_candidates(
                symbols, dependency_walk, identity_report.get("system_dependency_candidates", {}))
            if linker_config is not None:
                identity_report["namespace_candidate_audit"] = donor_namespace_candidates(
                    linker_config, linker_config_sha, dependency_walk,
                    identity_report.get("system_dependency_candidates", {}))
        current = image.lstat()
        if (current.st_dev, current.st_ino, current.st_mode, current.st_size,
                current.st_mtime_ns, current.st_ctime_ns) != source_identity:
            raise ValueError("Donor image changed")
        if image_info(snapshot) != before:
            raise ValueError("Donor snapshot changed")
        report = {"status":"EXT4_DONOR_EXTRACTION_ONLY","profile":profile,
                  "image_sha256":expected_sha,"snapshot_verified":True,"files":files,
                  "missing_or_ambiguous":[n for n,v in files.items() if v["status"]!="EXTRACTED"],
                  "donor_compatibility_verified":False,"xattrs_preserved":False,
                  "safe_to_flash":False}
        if profile == "vendor-identity":
            report["vendor_identity"] = identity_report
            report["vendor_identity"]["vendor_dependency_walk"] = dependency_walk
        (tree/"ext4-evidence.json").write_text(json.dumps(report,indent=2,sort_keys=True))
        os.rename(tree,output)
    return report


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--image",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True)
    p.add_argument("--profile",choices=PROFILES,required=True)
    p.add_argument("--sha256",required=True)
    p.add_argument("--system-image", type=Path)
    p.add_argument("--system-sha256")
    p.add_argument("--include-apex", action="store_true")
    p.add_argument("--linker-config", type=Path)
    p.add_argument("--linker-config-sha256")
    p.add_argument("--include-selinux", action="store_true")
    a=p.parse_args()
    report=extract(a.image,a.output,a.profile,a.sha256,a.system_image,a.system_sha256,a.include_apex,
                   a.linker_config,a.linker_config_sha256,a.include_selinux)
    print(json.dumps(report,sort_keys=True))
    identity = report.get("vendor_identity", {})
    review = identity.get("property_conflicts") or any(
        item["status"] != "ARM32_DYNAMIC" for item in identity.get("elf", {}).values())
    review = review or (identity and identity["vintf"]["status"] != "DECLARATIONS_PRESENT")
    review = review or (identity and identity["identity_inventory"]["status"] != "IDENTITY_FIELDS_PRESENT")
    return 2 if report["missing_or_ambiguous"] or review else 0


if __name__=="__main__":
    raise SystemExit(main())
