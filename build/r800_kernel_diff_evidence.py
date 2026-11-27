#!/usr/bin/env python3
"""Hash-only diagnostics for independent non-release kernel builds."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import os

BLOCK = 65536
MAX_FILE = 512 * 1024 * 1024
MAX_OBJECTS = 20000
MAX_REPORT = 16 * 1024 * 1024
GENERATED = ("include/generated/compile.h", "include/generated/utsrelease.h",
             "include/config/kernel.release", "System.map", "kernel/kheaders_data.tar.xz")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def read(path):
    if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= MAX_FILE:
        raise ValueError("Invalid diagnostic input: " + path.name)
    return path.read_bytes()


def sections(data):
    if data[:6] != b"\x7fELF\x02\x01" or len(data) < 64:
        raise ValueError("Expected little-endian ELF64")
    if struct.unpack_from("<H", data, 18)[0] != 183:
        raise ValueError("Expected AArch64 vmlinux")
    off = struct.unpack_from("<Q", data, 40)[0]
    entsize, count, names = struct.unpack_from("<HHH", data, 58)
    if entsize != 64 or not 0 < count <= 4096 or names >= count or off + count * entsize > len(data):
        raise ValueError("Invalid section table")
    rows = [struct.unpack_from("<IIQQQQIIQQ", data, off + i * entsize) for i in range(count)]
    def payload(row):
        start, size = row[4:6]
        if start + size > len(data):
            raise ValueError("Section outside ELF")
        return data[start:start + size]
    strings = payload(rows[names])
    result = {}
    for row in rows:
        name, kind, flags, address, _, size = row[:6]
        if not flags & 2 or kind == 8:  # allocatable file-backed sections
            continue
        end = strings.find(b"\0", name)
        if end < 0:
            raise ValueError("Invalid section name")
        key = strings[name:end].decode("ascii")
        if not key or key in result:
            raise ValueError("Empty or duplicate section name")
        result[key] = {"address": address, "bytes": size, "sha256": digest(payload(row))}
    if not result:
        raise ValueError("No allocatable sections")
    return result


def object_inventory(root):
    """Hash compiled inputs and selected generated metadata; never export bytes."""
    from r800_reproducibility_audit import hash_file

    paths = []
    for directory, subdirs, names in os.walk(root, followlinks=False):
        subdirs.sort()
        for name in sorted(names):
            if name.endswith(".o"):
                paths.append(Path(directory) / name)
                if len(paths) > MAX_OBJECTS:
                    raise ValueError("Too many kernel objects")
    if not paths:
        raise ValueError("No compiled kernel objects")
    for name in GENERATED:
        paths.append(root / name)
    records = {}
    for path in paths:
        name = path.relative_to(root).as_posix()
        if len(name) > 512 or not name.isascii() or not name.isprintable():
            raise ValueError("Invalid kernel object path")
        sha, size = hash_file(path, MAX_FILE)
        records[name] = {"sha256": sha, "bytes": size}
    return dict(sorted(records.items()))


def snapshot(root, include_objects=False):
    image = read(root / "arch/arm64/boot/Image")
    if image[56:60] != b"ARM\x64":
        raise ValueError("Invalid ARM64 Image")
    elf = read(root / "vmlinux")
    result = {
        "schema": "galwear-kernel-diagnostic-v1",
        "image_sha256": digest(image),
        "image_bytes": len(image),
        "block_bytes": BLOCK,
        "blocks": [digest(image[i:i+BLOCK]) for i in range(0, len(image), BLOCK)],
        "sections": sections(elf),
        "safe_to_flash": False,
    }
    if include_objects:
        result["objects"] = object_inventory(root)
    return result


def read_report(path):
    if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= MAX_REPORT:
        raise ValueError("Invalid diagnostic report: " + path.name)

    def unique(pairs):
        obj = {}
        for key, value in pairs:
            if key in obj:
                raise ValueError("Duplicate JSON key")
            obj[key] = value
        return obj

    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique)


def validate_diagnostic(report, manifest):
    from r800_reproducibility_audit import SHA256, validate_manifest

    validate_manifest(manifest)
    if not isinstance(report, dict) or report.get("schema") != "galwear-kernel-diagnostic-v1":
        raise ValueError("Unknown diagnostic schema")
    if report.get("safe_to_flash") is not False or report.get("block_bytes") != BLOCK:
        raise ValueError("Invalid diagnostic flags or block size")
    for field in ("image_sha256", "image_bytes"):
        if type(report.get(field)) is not type(manifest[field]) or report[field] != manifest[field]:
            raise ValueError("Diagnostic not bound to Image manifest: " + field)
    blocks = report.get("blocks")
    if not isinstance(blocks, list) or len(blocks) != (manifest["image_bytes"] + BLOCK - 1) // BLOCK:
        raise ValueError("Incorrect Image block count")
    if not all(isinstance(value, str) and SHA256.fullmatch(value) for value in blocks):
        raise ValueError("Invalid Image block hash")
    entries = report.get("sections")
    if not isinstance(entries, dict) or not 0 < len(entries) <= 4096:
        raise ValueError("Invalid section inventory")
    for name, row in entries.items():
        if not isinstance(name, str) or not name or not name.isascii() or not name.isprintable():
            raise ValueError("Invalid section name")
        if not isinstance(row, dict) or set(row) != {"address", "bytes", "sha256"}:
            raise ValueError("Invalid section record")
        if (type(row["address"]) is not int or not 0 <= row["address"] < 2**64 or
                type(row["bytes"]) is not int or not 0 <= row["bytes"] <= MAX_FILE or
                not isinstance(row["sha256"], str) or not SHA256.fullmatch(row["sha256"])):
            raise ValueError("Invalid section metadata")


def validate_objects(records):
    from r800_reproducibility_audit import SHA256

    if not isinstance(records, dict) or not 1 <= len(records) <= MAX_OBJECTS + len(GENERATED):
        raise ValueError("Invalid kernel object inventory")
    if not set(GENERATED).issubset(records) or not any(name.endswith(".o") for name in records):
        raise ValueError("Incomplete kernel object inventory")
    for name, row in records.items():
        if (not isinstance(name, str) or not name or len(name) > 512 or
                not name.isascii() or not name.isprintable() or
                any(part in ("", ".", "..") for part in name.split("/")) or
                "\\" in name or (name not in GENERATED and not name.endswith(".o"))):
            raise ValueError("Invalid kernel object path")
        if (not isinstance(row, dict) or set(row) != {"bytes", "sha256"} or
                type(row["bytes"]) is not int or not 0 < row["bytes"] <= MAX_FILE or
                not isinstance(row["sha256"], str) or not SHA256.fullmatch(row["sha256"])):
            raise ValueError("Invalid kernel object record")


def compare(first, second, image_a, image_b):
    validate_diagnostic(first, image_a)
    validate_diagnostic(second, image_b)
    for field in ("galwear_commit", "run_id", "run_attempt"):
        if image_a[field] != image_b[field]:
            raise ValueError("Diagnostic build identity mismatch: " + field)
    if (image_a["runner_replica"], image_b["runner_replica"]) != ("a", "b"):
        raise ValueError("Expected distinct matrix replicas a and b")
    a, b = first["blocks"], second["blocks"]
    changed = [i for i in range(max(len(a), len(b)))
               if i >= len(a) or i >= len(b) or a[i] != b[i]]
    equal = image_a["image_sha256"] == image_b["image_sha256"]
    if equal != (not changed and first["image_bytes"] == second["image_bytes"]):
        raise ValueError("Inconsistent whole Image and block hashes")
    sa, sb = first["sections"], second["sections"]
    differences = {}
    for name in sorted(sa.keys() | sb.keys()):
        if sa.get(name) != sb.get(name):
            differences[name] = {"a": sa.get(name), "b": sb.get(name)}
    objects_a, objects_b = first.get("objects"), second.get("objects")
    object_differences = None
    if "objects" in first or "objects" in second:
        validate_objects(objects_a)
        validate_objects(objects_b)
        object_differences = {
            name: {"a": objects_a.get(name), "b": objects_b.get(name)}
            for name in sorted(objects_a.keys() | objects_b.keys())
            if objects_a.get(name) != objects_b.get(name)
        }
    return {
        "schema": "galwear-kernel-diagnostic-comparison-v1",
        "status": "IMAGE_HASH_MATCH" if equal else "IMAGE_HASH_MISMATCH",
        "galwear_commit": image_a["galwear_commit"],
        "run_id": image_a["run_id"],
        "run_attempt": image_a["run_attempt"],
        "block_bytes": BLOCK,
        "different_blocks": len(changed),
        "first_different_block_offset": changed[0] * BLOCK if changed else None,
        "last_different_block_offset": changed[-1] * BLOCK if changed else None,
        "different_block_offsets": [i * BLOCK for i in changed],
        "different_sections": differences,
        "object_inventory_compared": object_differences is not None,
        "different_objects": object_differences,
        "diagnostic_only": True,
        "safe_to_flash": False,
    }


def compare_directory(root):
    a, b = (root / ("r800-image-evidence-" + replica) for replica in ("a", "b"))
    return compare(read_report(a / "r800-kernel-diff-evidence.json"),
                   read_report(b / "r800-kernel-diff-evidence.json"),
                   read_report(a / "r800-image-repeatability.json"),
                   read_report(b / "r800-image-repeatability.json"))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    mode = p.add_mutually_exclusive_group(required=True)
    mode.add_argument("--root", type=Path)
    mode.add_argument("--compare-dir", type=Path)
    p.add_argument("--include-objects", action="store_true")
    p.add_argument("--output", required=True, type=Path)
    a = p.parse_args()
    if a.include_objects and not a.root:
        p.error("--include-objects requires --root")
    result = snapshot(a.root, a.include_objects) if a.root else compare_directory(a.compare_dir)
    with a.output.open("x", encoding="utf-8") as f:
        json.dump(result, f, indent=2, sort_keys=True)
        f.write("\n")


if __name__ == "__main__":
    main()
