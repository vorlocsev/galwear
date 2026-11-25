#!/usr/bin/env python3
"""Plan a single-namespace experimental Android init rootfs, never boot it.

Different-content candidates require explicit selection. The graph is recomputed
from the source trees, not trusted from a previously saved JSON report.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

from r800_android_init_dependencies import graph, regular, MAX_NODES, MAX_TOTAL
from r800_android_init_inventory import MODULES
from r800_android_dynamic_audit import RUNTIME

SEARCH = ("/system/lib64/bootstrap", "/system/lib64",
          "/" + RUNTIME + "/lib64/bionic")
CONFIG = ("# GalWear experimental single namespace; not Android linkerconfig\n"
          "dir.galwear = /system/bin\n[galwear]\n"
          "namespace.default.isolated = true\n"
          "namespace.default.search.paths = " + ":".join(SEARCH) + "\n"
          "namespace.default.permitted.paths = " + ":".join(SEARCH) + "\n").encode()
HASH = re.compile(r"[0-9a-f]{64}")


def plan(report: dict, choices: dict) -> dict:
    if report.get("status") != "INIT_DEPENDENCY_CANDIDATES_ONLY":
        raise ValueError("Candidate inventory required")
    if set(choices) != {"libraries", "interpreters"}:
        raise ValueError("Expected libraries and interpreters selection maps")
    libraries, interpreters = choices["libraries"], choices["interpreters"]
    if not isinstance(libraries, dict) or not isinstance(interpreters, dict):
        raise ValueError("Invalid selection maps")
    nodes = report["nodes"]
    edges = {(e["from"], e["needed"]): e["candidates"] for e in report["edges"]}
    selected = {}
    files = {}
    aliases = {}
    used = set()
    pending = []

    def add(key):
        info = nodes[key]
        origin, rel = key.split(":", 1)
        if origin not in ("product", "runtime") or not HASH.fullmatch(info["sha256"]):
            raise ValueError("Invalid source identity")
        path = Path(rel)
        if path.is_absolute() or ".." in path.parts or str(path) != rel:
            raise ValueError("Invalid guest path")
        value = {"source": key, "sha256": info["sha256"], "size_bytes": info["size_bytes"]}
        if rel in files and files[rel] != value:
            raise ValueError("Conflicting guest path: " + rel)
        files[rel] = value

    required_interpreters = set()
    for module in sorted(MODULES):
        info = report["modules"][module]
        key = "product:" + info["path"]
        add(key)
        pending.append(key)
        required_interpreters.add(info["interpreter"])
    if set(interpreters) != required_interpreters:
        raise ValueError("Explicit mapping required for each PT_INTERP")
    for interp, key in interpreters.items():
        if key not in report["linkers"]:
            raise ValueError("Interpreter choice is not an audited linker")
        add(key)
        target = key.split(":", 1)[1]
        guest = interp.lstrip("/")
        if guest != target:
            # The only supported alias is the standard system linker to the
            # runtime APEX, or to the audited bootstrap linker.
            if guest != "system/bin/linker64" or target not in (
                    RUNTIME + "/bin/linker64", "system/bin/bootstrap/linker64"):
                raise ValueError("Unsupported interpreter alias")
            aliases[guest] = "/" + target
    visited = set()
    while pending:
        key = pending.pop()
        if key in visited:
            continue
        visited.add(key)
        for name in nodes[key]["needed"]:
            candidates = edges.get((key, name), [])
            if not candidates:
                raise ValueError("Missing dependency: " + name)
            if name in libraries:
                chosen = libraries[name]
                used.add(name)
                if chosen not in candidates:
                    raise ValueError("Selected library not a candidate: " + name)
            else:
                if len({nodes[c]["sha256"] for c in candidates}) != 1:
                    raise ValueError("Explicit library selection required: " + name)
                chosen = sorted(candidates)[0]
            if name in selected and selected[name] != chosen:
                raise ValueError("Inconsistent library selection: " + name)
            selected[name] = chosen
            add(chosen)
            pending.append(chosen)
    if used != set(libraries):
        raise ValueError("Unused library selections")
    if set(aliases) & set(files):
        raise ValueError("Interpreter alias collides with real file")
    if len(files) > MAX_NODES or sum(f["size_bytes"] for f in files.values()) > MAX_TOTAL:
        raise ValueError("Rootfs plan exceeds bounds")
    return {"status": "INIT_EXPERIMENTAL_ROOTFS_PLAN_ONLY", "files": files,
            "interpreter_aliases": aliases, "selected_libraries": selected,
            "linkerconfig_sha256": hashlib.sha256(CONFIG).hexdigest(),
            "namespace_resolution_tested": False, "android_init_started": False,
            "property_service_started": False, "safe_to_flash": False}


def stage(result, product, runtime, out):
    roots = {"product": product.resolve(strict=True)}
    if runtime is not None:
        roots["runtime"] = runtime.resolve(strict=True)
    # Verify every source before creating any output.
    data = {}
    for rel, info in result["files"].items():
        origin, source = info["source"].split(":", 1)
        path = regular(roots[origin], source)
        if path is None:
            raise ValueError("Missing source: " + source)
        with path.open("rb") as stream:
            blob = stream.read(info["size_bytes"] + 1)
        if len(blob) != info["size_bytes"] or hashlib.sha256(blob).hexdigest() != info["sha256"]:
            raise ValueError("Source changed: " + source)
        data[rel] = blob
    out.mkdir(exist_ok=False)
    for rel, blob in data.items():
        path = out / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(blob)
        path.chmod(0o644)  # deliberately not executable on host
    # Keep guest symlinks as manifest data only; never create absolute host links.
    (out / "linkerconfig").mkdir()
    (out / "linkerconfig/ld.config.txt").write_bytes(CONFIG)
    (out / "guest-layout.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--product-out", type=Path, required=True)
    p.add_argument("--runtime-root", type=Path)
    p.add_argument("--choices", type=Path, required=True)
    p.add_argument("--out", type=Path)
    p.add_argument("--report", type=Path, required=True)
    p.add_argument("--readelf", default="readelf")
    a = p.parse_args()
    try:
        with a.choices.open("rb") as f:
            raw = f.read(65537)
        if len(raw) > 65536:
            raise ValueError("Selection file too large")
        result = plan(graph(a.product_out, a.runtime_root, a.readelf), json.loads(raw))
        if a.out:
            stage(result, a.product_out, a.runtime_root, a.out)
            result["status"] = "INIT_EXPERIMENTAL_ROOTFS_STAGED_ONLY"
        rc = 0
    except (OSError, ValueError, KeyError, TypeError, RuntimeError, subprocess.SubprocessError) as exc:
        result = {"status": "REJECT", "reason": str(exc), "safe_to_flash": False}
        rc = 2
    a.report.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(result["status"])
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
