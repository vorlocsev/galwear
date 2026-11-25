#!/usr/bin/env python3
"""Bounded, read-only DT_NEEDED graph for Android 11 init/service/client.

This is an explicit candidate inventory, not Android namespace emulation.
No host library lookup, arbitrary symlink traversal, dlopen or execution.
A build tree and an extracted runtime APEX may be separate inputs.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import re
import subprocess

from r800_android_dynamic_audit import inspect_elf, RUNTIME
from r800_android_init_inventory import inventory, MODULES

MAX_NODES = 256
MAX_TOTAL = 256 * 1024 * 1024
LIBRARY = re.compile(r"[A-Za-z0-9_.+-]+\.so")
SYSTEM_DIRS = ("system/lib64", "system/lib64/bootstrap")
RUNTIME_DIR = RUNTIME + "/lib64/bionic"
LINKER_LOCATIONS = ("system/bin/bootstrap/linker64", "system/bin/linker64",
                    RUNTIME + "/bin/linker64")


def regular(root: Path, relative: str):
    rel = Path(relative)
    if rel.is_absolute() or not rel.parts or ".." in rel.parts or str(rel) != relative:
        return None
    root = root.absolute()
    p = root / rel
    # Reject absolute paths, traversal and symlinks at every component.
    try:
        if p.resolve() != p or p.is_symlink() or not p.is_file():
            return None
    except (OSError, RuntimeError):
        return None
    return p


def graph(product: Path, runtime: Path | None, readelf: str = "readelf"):
    product = product.resolve(strict=True)
    runtime = runtime.resolve(strict=True) if runtime is not None else None
    roots = {"product": product}
    if runtime is not None:
        roots["runtime"] = runtime
    base = inventory(product, readelf)
    nodes, edges, missing, ambiguous = {}, [], set(), {}
    total = 0

    def record(key, path, info):
        nonlocal total
        if key not in nodes:
            total += info["size_bytes"]
            if len(nodes) >= MAX_NODES or total > MAX_TOTAL:
                raise ValueError("Dependency graph exceeds bounds")
            nodes[key] = info

    def candidates(name):
        if not LIBRARY.fullmatch(name):
            raise ValueError("Invalid dependency basename")
        result = []
        for origin, directory in (
            [("product", d) for d in SYSTEM_DIRS] +
            [("runtime" if runtime is not None else "product", RUNTIME_DIR)]
        ):
            rel = directory + "/" + name
            p = regular(roots[origin], rel)
            if p is not None:
                key = origin + ":" + rel
                info = nodes.get(key)
                if info is None:
                    info = inspect_elf(p, readelf)
                    if (info["elf_type"] != 3 or info["interpreter"] is not None
                            or info["soname"] != name):
                        raise ValueError("Unexpected library identity: " + key)
                    record(key, p, info)
                result.append(key)
        return result

    pending = []
    for module in sorted(MODULES):
        info = base["modules"][module]
        key = "product:" + info["path"]
        record(key, product / info["path"], info)
        pending.append(key)
    visited = set()
    while pending:
        parent = pending.pop()
        if parent in visited:
            continue
        visited.add(parent)
        for name in nodes[parent]["needed"]:
            found = candidates(name)
            edges.append({"from": parent, "needed": name, "candidates": found})
            if not found:
                missing.add(name)
            elif len({nodes[key]["sha256"] for key in found}) > 1:
                ambiguous[name] = found
            pending.extend(found)
    linkers = {}
    for rel in LINKER_LOCATIONS:
        origin = "runtime" if runtime is not None and rel.startswith(RUNTIME + "/") else "product"
        p = regular(roots[origin], rel)
        if p is None:
            continue
        key = origin + ":" + rel
        info = inspect_elf(p, readelf)
        if info["elf_type"] != 3 or info["interpreter"] is not None or info["needed"]:
            raise ValueError("Unexpected linker identity: " + key)
        record(key, p, info)
        linkers[key] = info
    return {
        "status": "INIT_DEPENDENCY_CANDIDATES_ONLY",
        "modules": base["modules"], "nodes": nodes, "edges": edges,
        "missing": sorted(missing), "ambiguous": ambiguous,
        "linkers": linkers, "total_candidate_bytes": total,
        "all_dt_needed_have_candidates": not missing,
        "unambiguous_candidate_graph": not missing and not ambiguous,
        "dependency_closure_verified": False,
        "namespace_resolution_tested": False,
        "dlopen_dependencies_tested": False,
        "android_init_started": False, "property_service_started": False,
        "safe_to_flash": False,
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--product-out", type=Path, required=True)
    p.add_argument("--runtime-root", type=Path)
    p.add_argument("--readelf", default="readelf")
    p.add_argument("--report", type=Path, required=True)
    a = p.parse_args()
    try:
        result = graph(a.product_out, a.runtime_root, a.readelf)
        rc = 0
    except (OSError, ValueError, subprocess.SubprocessError, RuntimeError) as exc:
        result = {"status": "REJECT", "reason": str(exc), "safe_to_flash": False}
        rc = 2
    a.report.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(result["status"])
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
