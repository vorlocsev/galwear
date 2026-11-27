#!/usr/bin/env python3
"""Audit actual merged vendor ELF objects before image packing; no execution."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import stat

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
    a = p.parse_args()
    if a.report.resolve().is_relative_to(a.tree.resolve()):
        p.error("Report must be outside vendor tree")
    try:
        report = audit(a.tree)
    except (OSError, ValueError, RuntimeError) as exc:
        report = {"status": "REVIEW_REQUIRED", "reason": str(exc), "safe_to_flash": False}
    with a.report.open("x", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2, sort_keys=True)
        stream.write("\n")
    print(report["status"])
    return 0 if report["status"] == "MERGED_VENDOR_LOCAL_GRAPH_ONLY" else 2


if __name__ == "__main__":
    raise SystemExit(main())
