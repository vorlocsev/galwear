#!/usr/bin/env python3
"""Literal ART classpath evidence from explicitly mapped, hash-pinned partitions.

Only selected init RC files and framework JAR/DEX paths are read. No init import
expansion, APEX activation, class loading, or Android execution.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import tempfile
import zipfile

from r800_art_inventory import CLASSPATHS, MAX_PATHS, MAX_TOTAL, jar_inventory, dex_inventory
from r800_init_inventory import parse, MAX_RC
from r800_extract_ext4 import snapshot_image
from r800_extract_super import ALLOWED, require
from r800_partition_identity import filesystem
from r800_framework_inventory import ext4_member, erofs_member, bounded_tool, MAX_TOOL, MAX_META
from r800_graphics_donor_binding import checkout_sha
from r800_donor_preflight import digest
from r800_art_apex_mapping import ApexReader

MAX_IMAGE = 4*1024**3
MAX_IMAGES = 5
MAX_RCS = 16
RC_PATH = re.compile(r"/(?:system|system_ext|product|vendor|odm)/(?:etc/init/(?:hw/)?)?[A-Za-z0-9_.-]+\.rc")
ART_PATH = re.compile(r"/(?:system|system_ext|product|vendor|odm)/framework/[A-Za-z0-9_.-]+\.(?:jar|dex)")
APEX_PATH = re.compile(r"/apex/[A-Za-z0-9_.@-]+/javalib/[A-Za-z0-9_.-]+\.(?:jar|dex)")


def map_images(specs):
    require(1 <= len(specs) <= MAX_IMAGES, "Invalid partition count")
    rows, suffixes = {}, set()
    for partition, path, pin, prefix in specs:
        require(ALLOWED.fullmatch(partition) and re.fullmatch(r"[0-9a-f]{64}", pin),
                "Invalid partition name or SHA-256")
        base = re.sub(r"_[ab]$", "", partition)
        suffixes.add(partition[len(base):])
        require(base not in rows and prefix in ("", "/"+base), "Duplicate partition or wrong prefix")
        rows[base] = {"partition": partition, "image": Path(path), "sha256": pin, "prefix": prefix}
    require(len(suffixes) == 1, "Mixed or unspecified partition slots")
    return rows


def read_mapped(rows, path, limit, scratch):
    base, relative = path[1:].split("/", 1)
    row = rows.get(base)
    if row is None:
        raise ValueError("No explicit partition image for /"+base)
    return row["reader"](row["tool"], row["snapshot"], row["prefix"]+"/"+relative,
                         limit, scratch)


def literal_exports(sources):
    exports = {key: [] for key in CLASSPATHS}
    imports, errors = [], []
    for path, raw in sources:
        try:
            _, actions, imported, _ = parse(raw.decode("utf-8"), path)
            imports.extend({"source": path, "path": target} for target in imported)
            for action in actions:
                for cmd in action["commands"]:
                    args = cmd["args"]
                    if cmd["name"] != "export" or not args or args[0] not in exports:
                        continue
                    if len(args) != 2:
                        errors.append(path+": invalid export "+args[0])
                        continue
                    paths = args[1].split(":")
                    if (not 1 <= len(paths) <= MAX_PATHS or len(set(paths)) != len(paths)
                            or not all(ART_PATH.fullmatch(p) or APEX_PATH.fullmatch(p) for p in paths)):
                        errors.append(path+": unsupported classpath "+args[0])
                        continue
                    exports[args[0]].append({"source": path, "line": cmd["line"],
                                               "trigger": action["trigger"], "paths": paths})
        except (ValueError, UnicodeError) as exc:
            errors.append(path+": "+str(exc))
    resolved = {}
    for key, records in exports.items():
        choices = {tuple(row["paths"]) for row in records}
        if len(choices) != 1:
            errors.append(key+": missing or conflicting literal exports")
        else:
            resolved[key] = list(next(iter(choices)))
    return exports, resolved, imports, errors


def audit(specs, rc_paths, source_sha, erofs_tool=None, erofs_tool_sha=None, apex_specs=()):
    checkout_sha(source_sha)
    rows = map_images(specs)
    require(1 <= len(rc_paths) <= MAX_RCS and len(set(rc_paths)) == len(rc_paths)
            and all(RC_PATH.fullmatch(p) for p in rc_paths), "Explicit allowed RC paths required")
    require((erofs_tool is None) == (erofs_tool_sha is None), "EROFS tool and SHA required together")
    artifacts, rc_evidence, sources, errors = {}, {}, [], []
    inputs = {}
    total = 0
    with tempfile.TemporaryDirectory(prefix="r800-art-partitions-") as tmp:
        scratch = Path(tmp)
        for base, row in rows.items():
            private = scratch/(base+".img")
            snapshot_image(row["image"], private, row["sha256"])
            fs = filesystem(private)
            if fs["kind"] == "EXT4":
                tool = shutil.which("debugfs")
                require(tool, "debugfs required")
                reader = ext4_member
            else:
                require(erofs_tool is not None and re.fullmatch(r"[0-9a-f]{64}", erofs_tool_sha),
                        "EROFS requires explicit pinned dump.erofs")
                tool = Path(erofs_tool).absolute()
                require(digest(tool, MAX_TOOL)["sha256"] == erofs_tool_sha, "EROFS tool SHA mismatch")
                require(b"--cat" in bounded_tool([str(tool), "--help"], MAX_META, scratch),
                        "EROFS tool lacks --cat")
                reader = erofs_member
            row.update(snapshot=private, tool=tool, reader=reader)
            inputs[base] = {"partition": row["partition"], "sha256": row["sha256"],
                            "prefix": row["prefix"], "filesystem": fs["kind"]}
        for path in rc_paths:
            try:
                raw = read_mapped(rows, path, MAX_RC, scratch)
                require(raw is not None, "RC file missing")
                rc_evidence[path] = {"sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}
                sources.append((path, raw))
            except (OSError, ValueError, RuntimeError) as exc:
                errors.append(path+": "+str(exc))
        exports, resolved, imports, export_errors = literal_exports(sources)
        errors.extend(export_errors)
        paths = list(dict.fromkeys(p for group in resolved.values() for p in group))
        require(len(paths) <= MAX_PATHS, "Aggregate classpath path budget exceeded")
        apex = ApexReader(apex_specs, lambda path, limit: read_mapped(rows, path, limit, scratch), scratch)
        for path in paths:
            is_apex = bool(APEX_PATH.fullmatch(path))
            if is_apex and path.split("/")[2] not in apex.specs:
                artifacts[path] = {"status": "APEX_PAYLOAD_NOT_MAPPED"}
                errors.append(path+": APEX activation and payload mapping not established")
                continue
            try:
                limit = min(64*1024**2, MAX_TOTAL-total)
                raw = apex.read(path, limit) if is_apex else read_mapped(rows, path, limit, scratch)
                require(raw is not None, "Classpath member missing")
                total += len(raw)
                require(total <= MAX_TOTAL, "ART byte budget exceeded")
                if path.endswith(".dex"):
                    result, used = {"status": "DEX_HEADER_INVENTORY_ONLY",
                                    "dex": {path: dex_inventory(raw)}}, 0
                else:
                    result, used = jar_inventory(raw, MAX_TOTAL-total)
                total += used
                artifacts[path] = {"sha256": hashlib.sha256(raw).hexdigest(),
                                   "bytes": len(raw), **result}
                if result["status"] == "NO_EMBEDDED_DEX":
                    errors.append(path+": precompiled ART evidence required")
            except (OSError, ValueError, RuntimeError, NotImplementedError, zipfile.BadZipFile) as exc:
                artifacts[path] = {"status": "REVIEW_REQUIRED"}
                errors.append(path+": "+str(exc))
                # A failed decompression may already have consumed work.
                # Do not spend the remaining aggregate budget after failure.
                break
        apex.verify_unchanged()
        for row in rows.values():
            require(digest(row["snapshot"], MAX_IMAGE)["sha256"] == row["sha256"] and
                    digest(row["image"], MAX_IMAGE)["sha256"] == row["sha256"],
                    "Partition input changed")
        if erofs_tool is not None:
            require(digest(Path(erofs_tool), MAX_TOOL)["sha256"] == erofs_tool_sha,
                    "EROFS tool changed")
    checkout_sha(source_sha)
    return {"schema": "galwear-r800-partition-art-classpath-v1", "source_sha": source_sha,
            "status": "SELECTED_LITERAL_CLASSPATH_DEX_HEADERS_ONLY" if not errors else "REVIEW_REQUIRED",
            "partition_inputs": inputs, "rc_inputs": rc_evidence, "exports": exports,
            "resolved_literal_paths": resolved, "unexpanded_imports": imports,
            "artifacts": artifacts, "errors": errors,
            "apex_packages": apex.evidence,
            "init_imports_resolved": False, "effective_classpath_verified": False,
            "apex_activation_verified": False, "oat_verified": False, "vdex_verified": False,
            "bytecode_verified": False, "art_initialization_verified": False,
            "hardware_tested": False, "safe_to_flash": False}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--image", nargs=4, action="append", required=True,
                   metavar=("PARTITION", "FILE", "SHA256", "PREFIX"))
    p.add_argument("--rc", action="append", required=True)
    p.add_argument("--source-sha", required=True)
    p.add_argument("--apex", nargs=3, action="append", default=[],
                   metavar=("MODULE", "GUEST_PATH", "SHA256"))
    p.add_argument("--erofs-tool", type=Path)
    p.add_argument("--erofs-tool-sha256")
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    report = audit(a.image, a.rc, a.source_sha, a.erofs_tool, a.erofs_tool_sha256, a.apex)
    with a.output.open("x", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2, sort_keys=True)
        stream.write("\n")
    print(report["status"])
    return 2 if report["errors"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
