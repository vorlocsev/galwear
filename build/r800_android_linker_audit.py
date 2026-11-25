#!/usr/bin/env python3
"""Bounded offline ELF DT_NEEDED inventory. Not Android namespace resolution."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import re
import struct

from r800_android_userspace_preflight import guest_path, read_regular, MAX_ELF

NAME = re.compile(r"[A-Za-z0-9_.+~-]{1,255}")
TARGETS = ("/init", "/system/bin/servicemanager", "/system/bin/hwservicemanager",
           "/vendor/bin/vndservicemanager", "/system/bin/app_process32")
MAX_NODES = 512


def inspect(data: bytes) -> dict:
    if len(data) < 52 or data[:4] != b"\x7fELF" or data[5:7] != b"\x01\x01":
        raise ValueError("Invalid little-endian ELF")
    cls = data[4]
    if cls not in (1, 2) or (cls == 2 and len(data) < 64):
        raise ValueError("Invalid ELF class")
    etype, machine = struct.unpack_from("<HH", data, 16)
    if etype not in (2, 3) or (cls, machine) not in ((1, 40), (2, 183)):
        raise ValueError("Unsupported ARM ELF")
    if cls == 2:
        phoff = struct.unpack_from("<Q", data, 32)[0]
        entsize, count = struct.unpack_from("<HH", data, 54)
        expected, dynfmt = 56, "<qQ"
    else:
        phoff = struct.unpack_from("<I", data, 28)[0]
        entsize, count = struct.unpack_from("<HH", data, 42)
        expected, dynfmt = 32, "<iI"
    if entsize != expected or not 1 <= count <= 128 or phoff + count * entsize > len(data):
        raise ValueError("Invalid program header table")
    loads, dynamic = [], None
    for i in range(count):
        p = phoff + i * entsize
        if cls == 2:
            typ, _, off, addr, _, size, mem, _ = struct.unpack_from("<IIQQQQQQ", data, p)
        else:
            typ, off, addr, _, size, mem, _, _ = struct.unpack_from("<IIIIIIII", data, p)
        if typ in (1, 2) and (off + size > len(data) or size > mem):
            raise ValueError("Invalid segment bounds")
        if typ == 1:
            loads.append((addr, off, size))
        if typ == 2:
            if dynamic is not None:
                raise ValueError("Duplicate PT_DYNAMIC")
            dynamic = (off, size)
    if not loads:
        raise ValueError("Missing PT_LOAD")
    result = {"abi": "arm64" if cls == 2 else "arm", "needed": [],
              "has_dynamic": dynamic is not None, "custom_search_path": False,
              "elf_type": "ET_DYN" if etype == 3 else "ET_EXEC"}
    if dynamic is None:
        return result
    off, size = dynamic
    step = struct.calcsize(dynfmt)
    if size % step or not 1 <= size // step <= 8192:
        raise ValueError("Invalid dynamic table size")
    tags = {}
    ended = False
    for p in range(off, off + size, step):
        tag, value = struct.unpack_from(dynfmt, data, p)
        if tag == 0:
            ended = True
            break
        tags.setdefault(tag, []).append(value)
    if not ended:
        raise ValueError("Missing DT_NULL")
    result["custom_search_path"] = 15 in tags or 29 in tags
    if 1 not in tags:
        return result
    if len(tags.get(5, [])) != 1 or len(tags.get(10, [])) != 1:
        raise ValueError("Missing or duplicate dynamic string table")
    addr, size = tags[5][0], tags[10][0]
    mappings = [fo + addr - va for va, fo, fs in loads
                if va <= addr and 0 < size <= fs - (addr - va)]
    if len(set(mappings)) != 1:
        raise ValueError("Dynamic string table not uniquely file-backed")
    strings = data[mappings[0]:mappings[0] + size]
    for index in tags[1]:
        if index >= len(strings):
            raise ValueError("DT_NEEDED offset outside string table")
        end = strings.find(b"\0", index)
        if end == -1 or end - index > 255:
            raise ValueError("Invalid DT_NEEDED string")
        name = strings[index:end].decode("ascii")
        if not NAME.fullmatch(name) or name in (".", ".."):
            raise ValueError("Unsafe dependency name")
        if name not in result["needed"]:
            result["needed"].append(name)
    return result


def directories(abi):
    lib = "lib64" if abi == "arm64" else "lib"
    return [f"/{base}/{lib}" for base in
            ("system", "system_ext", "vendor", "odm", "product",
             "apex/com.android.runtime", "apex/com.android.art")] + [
            f"/apex/com.android.runtime/{lib}/bionic"]


def audit(root: Path, targets=TARGETS) -> dict:
    queue = list(targets)
    seen, errors, unresolved, ambiguous = {}, [], [], []
    unsupported_search_paths = []
    while queue:
        name = queue.pop(0)
        if name in seen:
            continue
        if len(seen) >= MAX_NODES:
            errors.append("Dependency graph exceeds inspection limit")
            break
        seen[name] = None
        try:
            info = inspect(read_regular(guest_path(root, name), MAX_ELF))
        except (OSError, ValueError) as exc:
            errors.append(name + ": " + str(exc))
            continue
        seen[name] = info
        if info["custom_search_path"]:
            unsupported_search_paths.append(name)
        for dep in info["needed"]:
            candidates = {}
            for directory in directories(info["abi"]):
                path = directory + "/" + dep
                try:
                    resolved = guest_path(root, path)
                    child = inspect(read_regular(resolved, MAX_ELF))
                    if child["abi"] == info["abi"]:
                        if child["elf_type"] != "ET_DYN" or not child["has_dynamic"]:
                            errors.append(path + ": dependency is not a dynamic ET_DYN object")
                            continue
                        candidates.setdefault(str(resolved), path)
                except FileNotFoundError:
                    continue
                except (OSError, ValueError) as exc:
                    errors.append(path + ": " + str(exc))
            paths = sorted(candidates.values())
            if not paths:
                unresolved.append({"from": name, "needed": dep, "abi": info["abi"]})
            elif len(paths) > 1:
                ambiguous.append({"from": name, "needed": dep, "candidates": paths})
            queue.extend(p for p in paths if p not in seen and p not in queue)
    apex = {}
    for name in ("com.android.runtime", "com.android.art"):
        try:
            present = guest_path(root, "/apex/" + name).is_dir()
        except (OSError, ValueError):
            present = False
        apex[name] = {"expanded_tree_present": present}
    return {"schema": "galwear-r800-linker-inventory-v1",
            "status": "CANDIDATES_FOUND_ONLY" if not (errors or unresolved or ambiguous or unsupported_search_paths) else "REVIEW_REQUIRED",
            "objects": seen, "missing_candidates": unresolved, "ambiguous_candidates": ambiguous,
            "errors": errors, "unsupported_search_paths": unsupported_search_paths,
            "apex": apex, "android_namespace_resolution_verified": False,
            "symbol_versions_verified": False, "apex_activation_verified": False,
            "android_boot_tested": False, "safe_to_flash": False}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--root", required=True, type=Path)
    p.add_argument("--output", required=True, type=Path)
    args = p.parse_args()
    if args.output.resolve().is_relative_to(args.root.resolve()):
        p.error("Report must be outside guest root")
    result = audit(args.root)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(result["status"])
    return 0 if result["status"] == "CANDIDATES_FOUND_ONLY" else 2


if __name__ == "__main__":
    raise SystemExit(main())
