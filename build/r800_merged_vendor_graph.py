#!/usr/bin/env python3
"""Audit actual merged vendor ELF objects before image packing; no execution."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import stat
import shutil
import subprocess
import tempfile

from r800_android_userspace_preflight import read_regular
from r800_android_linker_audit import inspect

MAX_NODES = 512
MAX_FILE = 64 * 1024**2
MAX_TOTAL = 256 * 1024**2
MAX_EDGES = 8192
NAME = re.compile(r"[A-Za-z0-9_.+@~-]+")


def graph(objects):
    edges, conflicts = [], []
    names = {}
    for path, item in sorted(objects.items()):
        soname = item.get("soname")
        if soname:
            names.setdefault(soname, []).append(path)
    for name, paths in sorted(names.items()):
        if len({objects[p]["sha256"] for p in paths}) > 1:
            conflicts.append({"soname": name, "paths": paths})
    for path, item in sorted(objects.items()):
        for dep in sorted(set(item["needed"])):
            if len(edges) >= MAX_EDGES:
                raise ValueError("Dependency edge budget exceeded")
            if not NAME.fullmatch(dep) or dep in (".", ".."):
                raise ValueError("Invalid DT_NEEDED name")
            provider = "lib/" + dep
            found = objects.get(provider)
            if found is None:
                status = "EXTERNAL_OR_MISSING"
            elif found["elf_type"] != "ET_DYN" or found["soname"] not in (None, dep):
                status = "LOCAL_PROVIDER_REJECTED"
            else:
                status = "LOCAL_CANDIDATE_ONLY"
            edges.append({"from": path, "needed": dep, "candidate": provider, "status": status})
    return {"edges": edges, "soname_conflicts": conflicts,
            "external_or_missing": sorted({e["needed"] for e in edges
                                          if e["status"] == "EXTERNAL_OR_MISSING"}),
            "rejected_providers": [e for e in edges if e["status"] == "LOCAL_PROVIDER_REJECTED"]}


def vndk_version(root):
    values = set()
    for name in ("build.prop", "default.prop"):
        path = root/name
        try:
            raw = read_regular(path, 1024*1024)
        except FileNotFoundError:
            continue
        for line in raw.decode("utf-8").splitlines():
            key, sep, value = line.partition("=")
            if sep and key.strip() == "ro.vndk.version":
                values.add(value.strip())
    if len(values) > 1 or any(not re.fullmatch(r"[1-9][0-9]{0,2}", v) for v in values):
        raise ValueError("Conflicting or unsupported vendor VNDK version")
    return next(iter(values), None)


def external_audit(root, report, system_image, system_sha, include_apex):
    from r800_extract_ext4 import system_dependency_candidates
    if not re.fullmatch(r"[0-9a-f]{64}", system_sha):
        raise ValueError("Expected system SHA-256")
    tool = shutil.which("debugfs")
    if not tool:
        raise ValueError("debugfs required")
    version = vndk_version(root)
    # Reuse the snapshot-based recursive probe. The actual merged graph
    # supplies all external roots, not just the original HIDL selection.
    walk = {"external_names": report["external_or_missing"],
            "roots": sorted(report["objects"]), "budget_exhausted": False,
            "problems": report["rejected_objects"] + report["rejected_providers"] +
                        report["soname_conflicts"]}
    with tempfile.TemporaryDirectory(prefix="r800-merged-system-") as tmp:
        result = system_dependency_candidates(
            tool, system_image, system_sha, Path(tmp), walk,
            {"ro.vndk.version": version}, include_apex=include_apex)
    # The same library basename may appear in system and vendor. This is
    # evidence of competing candidates, not a simulated linker order.
    overlaps = []
    for name, row in sorted(result["system_candidate_graph"].items()):
        local = report["objects"].get("lib/" + name)
        if local is None:
            continue
        for candidate in row["candidates"]:
            if candidate["sha256"] != local["sha256"]:
                overlaps.append({"name": name, "vendor_sha256": local["sha256"],
                                 "system_sha256": candidate["sha256"],
                                 "system_origin": candidate["origin"],
                                 "system_path": candidate["path"]})
    result["different_vendor_system_candidates"] = overlaps
    if overlaps:
        result["status"] = "REVIEW_REQUIRED"
    return result


def audit(root):
    root = root.resolve(strict=True)
    objects, rejected = {}, []
    total = 0
    for directory in ("bin", "lib"):
        base = root/directory
        if not base.is_dir() or base.is_symlink():
            raise ValueError("Missing or symlinked vendor directory: " + directory)
        for path in sorted(base.rglob("*")):
            rel = path.relative_to(root).as_posix()
            mode = path.lstat().st_mode
            if stat.S_ISLNK(mode):
                rejected.append({"path": rel, "reason": "Symlink requires explicit review"})
                continue
            if stat.S_ISDIR(mode):
                continue
            if not stat.S_ISREG(mode):
                rejected.append({"path": rel, "reason": "Unexpected special file"})
                continue
            if not (directory == "bin" or path.name.endswith(".so")):
                continue
            if len(objects) + len(rejected) >= MAX_NODES:
                raise ValueError("ELF object budget exceeded")
            try:
                raw = read_regular(path, MAX_FILE)
                total += len(raw)
                if total > MAX_TOTAL:
                    raise RuntimeError("ELF byte budget exceeded")
                info = inspect(raw)
                if (info["abi"] != "arm" or not info["has_dynamic"] or
                        info["elf_type"] not in (("ET_DYN",) if directory == "lib" else ("ET_DYN", "ET_EXEC")) or
                        info["custom_search_path"]):
                    raise ValueError("Unexpected ARM32 dynamic ELF structure")
                objects[rel] = {"sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw),
                                "elf_type": info["elf_type"], "soname": info["soname"],
                                "needed": info["needed"]}
            except (OSError, ValueError, KeyError) as exc:
                rejected.append({"path": rel, "reason": str(exc)})
    if not objects:
        raise ValueError("No vendor ELF objects inspected")
    result = graph(objects)
    # Missing external providers are diagnostic until explicit system/VNDK inputs
    # exist. Locally rejected providers and SONAME conflicts stop packaging.
    blocked = bool(rejected or result["rejected_providers"] or result["soname_conflicts"])
    return {"status": "REVIEW_REQUIRED" if blocked else "MERGED_VENDOR_LOCAL_GRAPH_ONLY",
            "objects": objects, "rejected_objects": rejected, **result,
            "all_local_objects_inspected": not rejected, "external_resolution_verified": False,
            "namespace_resolution_verified": False, "symbol_closure_verified": False,
            "runtime_verified": False, "complete_vendor_image_built": False, "safe_to_flash": False}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--tree", type=Path, required=True)
    p.add_argument("--report", type=Path, required=True)
    p.add_argument("--system-image", type=Path)
    p.add_argument("--system-sha256")
    p.add_argument("--include-apex", action="store_true")
    a = p.parse_args()
    if a.report.resolve().is_relative_to(a.tree.resolve()):
        p.error("Report must be outside vendor tree")
    if bool(a.system_image) != bool(a.system_sha256) or (a.include_apex and not a.system_image):
        p.error("System image and digest required together; APEX requires system")
    try:
        report = audit(a.tree)
        if a.system_image is not None:
            external = external_audit(a.tree.resolve(strict=True), report,
                                      a.system_image, a.system_sha256, a.include_apex)
            report["system_candidates"] = external
            if (report["status"] == "MERGED_VENDOR_LOCAL_GRAPH_ONLY" and
                    external["status"] == "SYSTEM_PATH_CANDIDATES_ONLY"):
                report["status"] = "MERGED_VENDOR_SYSTEM_CANDIDATES_ONLY"
            else:
                report["status"] = "REVIEW_REQUIRED"
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        report = {"status": "REVIEW_REQUIRED", "reason": str(exc), "safe_to_flash": False}
    with a.report.open("x", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2, sort_keys=True)
        stream.write("\n")
    print(report["status"])
    return 0 if report["status"] in ("MERGED_VENDOR_LOCAL_GRAPH_ONLY", "MERGED_VENDOR_SYSTEM_CANDIDATES_ONLY") else 2


if __name__ == "__main__":
    raise SystemExit(main())
