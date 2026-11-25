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


DT_VERSYM = 0x6ffffff0
DT_VERDEF = 0x6ffffffc
DT_VERDEFNUM = 0x6ffffffd
DT_VERNEED = 0x6ffffffe
DT_VERNEEDNUM = 0x6fffffff
MAX_VERSION_RECORDS = 1024


def version_inventory(tags, data, loads, dynamic_name):
    def single(tag):
        values = tags.get(tag, [])
        if len(values) != 1:
            raise ValueError("Missing or duplicate version tag: " + hex(tag))
        return values[0]

    def read(addr, fmt):
        size = struct.calcsize(fmt)
        offsets = {fo + addr - va for va, fo, fs in loads
                   if va <= addr and size <= fs - (addr - va)}
        if len(offsets) != 1:
            raise ValueError("Version record not uniquely file-backed")
        return struct.unpack_from(fmt, data, offsets.pop())

    def advance(addr, delta, minimum, more):
        if not more:
            if delta:
                raise ValueError("Unexpected version chain continuation")
            return addr
        if delta < minimum or delta % 4:
            raise ValueError("Invalid version chain offset")
        return addr + delta

    def count(value):
        if not 1 <= value <= MAX_VERSION_RECORDS:
            raise ValueError("Invalid version record count")
        return value

    needs, definitions = [], []
    used_indices = set()
    budget = MAX_VERSION_RECORDS
    for addr_tag, num_tag, is_need in (
            (DT_VERNEED, DT_VERNEEDNUM, True),
            (DT_VERDEF, DT_VERDEFNUM, False)):
        if addr_tag not in tags and num_tag not in tags:
            continue
        addr, total = single(addr_tag), count(single(num_tag))
        for i in range(total):
            if is_need:
                version, naux, file_index, aux_delta, nxt = read(addr, "<HHIII")
                library = dynamic_name(file_index, "DT_VERNEED file")
                minimum = 16
            else:
                version, flags, index, naux, _, aux_delta, nxt = read(addr, "<HHHHIII")
                if index == 0 or index >= 0x8000 or index in used_indices:
                    raise ValueError("Invalid or duplicate version definition index")
                used_indices.add(index)
                minimum = 20
            if version != 1 or aux_delta < minimum or aux_delta % 4:
                raise ValueError("Invalid version record header")
            aux = addr + aux_delta
            names = []
            for j in range(count(naux)):
                budget -= 1
                if budget < 0:
                    raise ValueError("Version inventory exceeds inspection limit")
                if is_need:
                    _, flags, index, name_index, aux_next = read(aux, "<IHHII")
                    index &= 0x7fff
                    if index < 2 or index in used_indices:
                        raise ValueError("Invalid or duplicate version requirement index")
                    used_indices.add(index)
                    needs.append({"library": library, "version": dynamic_name(name_index, "DT_VERNEED name"),
                                  "weak": bool(flags & 2), "index": index})
                    aux = advance(aux, aux_next, 16, j + 1 < naux)
                else:
                    name_index, aux_next = read(aux, "<II")
                    names.append(dynamic_name(name_index, "DT_VERDEF name"))
                    aux = advance(aux, aux_next, 8, j + 1 < naux)
            if not is_need:
                definitions.append({"version": names[0], "parents": names[1:], "index": index,
                                    "base": bool(flags & 1)})
            addr = advance(addr, nxt, minimum, i + 1 < total)
    if DT_VERSYM in tags:
        read(single(DT_VERSYM), "<H")
    return needs, definitions, DT_VERSYM in tags


DT_HASH = 4
DT_SYMTAB = 6
DT_SYMENT = 11
DT_GNU_HASH = 0x6ffffef5
MAX_DYNAMIC_SYMBOLS = 262144


def symbol_inventory(tags, data, loads, cls, strings, result):
    def single(tag):
        values = tags.get(tag, [])
        if len(values) != 1:
            raise ValueError("Missing or duplicate symbol tag: " + hex(tag))
        return values[0]

    def offset(addr, size):
        matches = {fo + addr - va for va, fo, fs in loads
                   if va <= addr and 0 < size <= fs - (addr - va)}
        if len(matches) != 1:
            raise ValueError("Symbol table not uniquely file-backed")
        return matches.pop()

    present = any(t in tags for t in (DT_HASH, DT_SYMTAB, DT_SYMENT, DT_GNU_HASH))
    if not present:
        return
    fmt = "<IBBHQQ" if cls == 2 else "<IIIBBH"
    entry_size = struct.calcsize(fmt)
    symaddr = single(DT_SYMTAB)
    if single(DT_SYMENT) != entry_size:
        raise ValueError("Invalid DT_SYMENT")
    offset(symaddr, entry_size)
    if DT_HASH not in tags and DT_GNU_HASH not in tags:
        result["symbol_table_status"] = "COUNT_NOT_AVAILABLE"
        return
    count = None
    if DT_HASH in tags:
        addr = single(DT_HASH)
        buckets, count = struct.unpack_from("<II", data, offset(addr, 8))
        if not 1 <= buckets <= MAX_DYNAMIC_SYMBOLS or not 1 <= count <= MAX_DYNAMIC_SYMBOLS:
            raise ValueError("Invalid SYSV hash dimensions")
        pos = offset(addr, 8 + 4 * (buckets + count))
        indices = struct.unpack_from("<" + str(buckets + count) + "I", data, pos + 8)
        if any(i >= count for i in indices):
            raise ValueError("SYSV hash index out of bounds")
        if indices[buckets] != 0:
            raise ValueError("Nonzero SYSV chain zero entry")
        # Each chain node is traversed at most once globally.
        complete = {0}
        for start in indices[:buckets]:
            visiting = set()
            i = start
            while i not in complete:
                if i in visiting:
                    raise ValueError("Cyclic SYSV hash chain")
                visiting.add(i)
                i = indices[buckets + i]
            complete.update(visiting)
    gnu = None
    if DT_GNU_HASH in tags:
        addr = single(DT_GNU_HASH)
        buckets, first, bloom_size, shift = struct.unpack_from("<IIII", data, offset(addr, 16))
        if (not 1 <= buckets <= MAX_DYNAMIC_SYMBOLS or
                not 1 <= first <= MAX_DYNAMIC_SYMBOLS or
                not 1 <= bloom_size <= MAX_DYNAMIC_SYMBOLS or
                bloom_size & (bloom_size - 1) or shift >= 32):
            raise ValueError("Invalid GNU hash dimensions")
        word = 8 if cls == 2 else 4
        bits = word * 8
        header_size = 16 + bloom_size * word + buckets * 4
        pos = offset(addr, header_size)
        bloom = struct.unpack_from("<" + str(bloom_size) + ("Q" if cls == 2 else "I"), data, pos + 16)
        heads = struct.unpack_from("<" + str(buckets) + "I", data, pos + 16 + bloom_size * word)
        starts = sorted((head, bucket) for bucket, head in enumerate(heads) if head)
        chains = []
        expected = first
        for head, bucket in starts:
            if head != expected or head >= MAX_DYNAMIC_SYMBOLS:
                raise ValueError("Overlapping or noncontiguous GNU hash buckets")
            while True:
                if expected >= MAX_DYNAMIC_SYMBOLS:
                    raise ValueError("GNU hash chain exceeds inspection limit")
                entry_addr = addr + header_size + 4 * (expected - first)
                value, = struct.unpack_from("<I", data, offset(entry_addr, 4))
                chains.append((bucket, value))
                expected += 1
                if value & 1:
                    break
        if chains:
            offset(addr, header_size + 4 * len(chains))
        if count is not None and count != expected:
            raise ValueError("SYSV and GNU hash symbol counts disagree")
        count = expected
        gnu = (first, buckets, bloom, bits, shift, chains)
    pos = offset(symaddr, count * entry_size)
    vers = None
    if DT_VERSYM in tags:
        vers = struct.unpack_from("<" + str(count) + "H", data,
                                  offset(single(DT_VERSYM), count * 2))
    valid = {0, 1} | {v["index"] for v in result["version_needs"] + result["version_definitions"]}
    if vers is not None and any((v & 0x7fff) not in valid for v in vers):
        raise ValueError("DT_VERSYM references unknown version index")
    for i in range(count):
        name = struct.unpack_from("<I", data, pos + i * entry_size)[0]
        if name >= len(strings) or strings.find(b"\0", name, min(len(strings), name + 4096)) < 0:
            raise ValueError("Invalid dynamic symbol name")
    need_by_index = {v["index"]: v for v in result["version_needs"]}
    def_by_index = {v["index"]: v for v in result["version_definitions"]}
    imports, exports, unsupported = [], [], []
    name_bytes = 0
    for i in range(1, count):
        entry = struct.unpack_from(fmt, data, pos + i * entry_size)
        if cls == 2:
            name, info, other, section, _, _ = entry
        else:
            name, _, _, info, other, section = entry
        binding, typ, visibility = info >> 4, info & 15, other & 3
        if binding == 0:
            continue
        end = strings.find(b"\0", name, min(len(strings), name + 4096))
        if end == name:
            # Unnamed nonlocal symbols cannot be matched by name.
            continue
        raw_version = vers[i] if vers is not None else 1
        index = raw_version & 0x7fff
        requirement = need_by_index.get(index)
        definition = def_by_index.get(index)
        name_bytes += end - name
        if len(imports) + len(exports) + len(unsupported) >= 32768 or name_bytes > 4 * 1024 * 1024:
            raise ValueError("Symbol inventory exceeds reporting limit")
        record = {"name": strings[name:end].decode("utf-8", "surrogateescape"),
                  "index": i, "binding": binding, "type": typ,
                  "visibility": visibility, "weak": binding == 2,
                  "version": (requirement or definition or {}).get("version"),
                  "version_library": (requirement or {}).get("library"),
                  "version_hidden": bool(raw_version & 0x8000)}
        if binding not in (1, 2) or section == 0xffff:
            unsupported.append({**record, "reason": "binding_or_extended_section"})
        elif section == 0:
            if visibility in (1, 2, 3) or index == 0 or definition is not None:
                unsupported.append({**record, "reason": "nonstandard_undefined_symbol"})
            else:
                imports.append(record)
        elif visibility in (0, 3) and index != 0:
            if requirement is not None:
                unsupported.append({**record, "reason": "defined_symbol_with_version_requirement"})
            else:
                exports.append(record)
    result["symbol_imports"] = imports
    result["symbol_exports"] = exports
    result["unsupported_symbols"] = unsupported
    if gnu is not None:
        first, buckets, bloom, bits, shift, chains = gnu
        for i, (bucket, value) in enumerate(chains, first):
            name, = struct.unpack_from("<I", data, pos + i * entry_size)
            end = strings.find(b"\0", name, min(len(strings), name + 4096))
            h = 5381
            for byte in strings[name:end]:
                h = (h * 33 + byte) & 0xffffffff
            if h % buckets != bucket or (h & ~1) != (value & ~1):
                raise ValueError("GNU hash chain does not match symbol name")
            mask = (1 << (h % bits)) | (1 << ((h >> shift) % bits))
            if bloom[(h // bits) % len(bloom)] & mask != mask:
                raise ValueError("GNU hash Bloom filter misses symbol")
    result["dynamic_symbol_count"] = count
    result["symbol_table_status"] = ("SYSV_AND_GNU_STRUCTURE_CHECKED" if DT_HASH in tags and gnu is not None
                                     else "GNU_STRUCTURE_CHECKED" if gnu is not None else "SYSV_STRUCTURE_CHECKED")
    result["versym_indices_checked"] = vers is not None


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
              "elf_type": "ET_DYN" if etype == 3 else "ET_EXEC", "soname": None,
              "version_needs": [], "version_definitions": [], "versym_present": False,
              "dynamic_symbol_count": None, "symbol_table_status": "NOT_PRESENT",
              "versym_indices_checked": False, "symbol_imports": [],
              "symbol_exports": [], "unsupported_symbols": []}
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
    if len(tags.get(14, [])) > 1:
        raise ValueError("Duplicate DT_SONAME")
    if not any(tag in tags for tag in (1, 14, DT_VERNEED, DT_VERNEEDNUM, DT_VERDEF, DT_VERDEFNUM, DT_VERSYM, DT_HASH, DT_SYMTAB, DT_SYMENT, DT_GNU_HASH)):
        return result
    if len(tags.get(5, [])) != 1 or len(tags.get(10, [])) != 1:
        raise ValueError("Missing or duplicate dynamic string table")
    addr, size = tags[5][0], tags[10][0]
    mappings = [fo + addr - va for va, fo, fs in loads
                if va <= addr and 0 < size <= fs - (addr - va)]
    if len(set(mappings)) != 1:
        raise ValueError("Dynamic string table not uniquely file-backed")
    strings = data[mappings[0]:mappings[0] + size]
    def dynamic_name(index, label):
        if index >= len(strings):
            raise ValueError(label + " offset outside string table")
        end = strings.find(b"\0", index)
        if end == -1 or end - index > 255:
            raise ValueError("Invalid " + label + " string")
        name = strings[index:end].decode("ascii")
        if not NAME.fullmatch(name) or name in (".", ".."):
            raise ValueError("Unsafe dependency name: " + label)
        return name

    for index in tags.get(1, []):
        name = dynamic_name(index, "DT_NEEDED")
        if name not in result["needed"]:
            result["needed"].append(name)
    if 14 in tags:
        result["soname"] = dynamic_name(tags[14][0], "DT_SONAME")
    result["version_needs"], result["version_definitions"], result["versym_present"] = version_inventory(tags, data, loads, dynamic_name)
    symbol_inventory(tags, data, loads, cls, strings, result)
    return result


def directories(abi):
    lib = "lib64" if abi == "arm64" else "lib"
    return [f"/{base}/{lib}" for base in
            ("system", "system_ext", "vendor", "odm", "product",
             "apex/com.android.runtime", "apex/com.android.art")] + [
            f"/apex/com.android.runtime/{lib}/bionic"]


def symbol_candidates(seen, edges):
    """Potential providers in dependency closure, not Android lookup order."""
    missing, weak_missing, ambiguous, incomplete = [], [], [], []
    matched = 0
    budget = 4000000
    # Index exports once; the closure and version constraints are applied below.
    by_name = {}
    for path, info in seen.items():
        if info is not None:
            for symbol in info["symbol_exports"]:
                by_name.setdefault((info["abi"], symbol["name"]), []).append((path, symbol))

    def closure(start):
        reached, pending = set(), [start]
        while pending:
            path = pending.pop()
            if path in reached:
                continue
            reached.add(path)
            pending.extend(p for group in edges.get(path, {}).values() for p in group
                           if p not in reached)
        return reached

    def compatible(required, provided):
        # NOTYPE is deliberately permissive; TLS cannot match non-TLS.
        if (required["type"] == 6) != (provided["type"] == 6):
            return False
        if required["version"] is not None:
            return required["version"] == provided["version"]
        return not provided["version_hidden"]

    for path, info in seen.items():
        if info is None or not info["symbol_imports"]:
            continue
        reachable = closure(path)
        uncertain = any(seen.get(p) is None or
                        (seen[p]["has_dynamic"] and seen[p]["dynamic_symbol_count"] is None)
                        for p in reachable)
        uncertain |= any(not group for p in reachable for group in edges.get(p, {}).values())
        for required in info["symbol_imports"]:
            record = {"from": path, **required}
            allowed = reachable
            if required["version_library"] is not None:
                allowed = set(edges.get(path, {}).get(required["version_library"], ()))
            providers = {}
            for provider, symbol in by_name.get((info["abi"], required["name"]), ()):
                budget -= 1
                if budget < 0:
                    return {"matched": matched, "missing_strong": missing, "missing_weak": weak_missing,
                            "ambiguous": ambiguous, "incomplete": incomplete, "limit_exceeded": True}
                if provider in allowed and compatible(required, symbol):
                    providers[provider] = providers.get(provider, True) and symbol["weak"]
            if not providers:
                if uncertain:
                    incomplete.append(record)
                elif required["weak"]:
                    weak_missing.append(record)
                else:
                    missing.append(record)
            elif len(providers) > 1:
                ambiguous.append({**record, "providers": sorted(providers),
                                  "strong_providers": sorted(p for p in providers if not providers[p])})
            else:
                matched += 1
    return {"matched": matched, "missing_strong": missing, "missing_weak": weak_missing,
            "ambiguous": ambiguous, "incomplete": incomplete, "limit_exceeded": False}


def audit(root: Path, targets=TARGETS) -> dict:
    queue = list(targets)
    seen, errors, unresolved, ambiguous = {}, [], [], []
    unsupported_search_paths, soname_mismatches = [], []
    version_mismatches, unbound_version_needs = [], []
    unsupported_symbol_objects = []
    edges = {}
    inventory_records = 0
    inventory_name_bytes = 0
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
        symbols = info["symbol_imports"] + info["symbol_exports"] + info["unsupported_symbols"]
        inventory_records += len(symbols)
        inventory_name_bytes += sum(len(v["name"].encode("utf-8", "surrogateescape")) for v in symbols)
        if inventory_records > 131072 or inventory_name_bytes > 16 * 1024 * 1024:
            errors.append("Aggregate symbol inventory exceeds reporting limit")
            break
        seen[name] = info
        edges[name] = {}
        if info["unsupported_symbols"]:
            unsupported_symbol_objects.append(name)
        if info["custom_search_path"]:
            unsupported_search_paths.append(name)
        for requirement in info["version_needs"]:
            if requirement["library"] not in info["needed"]:
                unbound_version_needs.append({"from": name, **requirement})
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
                        if child["soname"] is not None and child["soname"] != dep:
                            soname_mismatches.append({"from": name, "needed": dep,
                                                     "candidate": path, "soname": child["soname"]})
                        if str(resolved) not in candidates:
                            defined = {v["version"] for v in child["version_definitions"] if not v["base"]}
                            for requirement in info["version_needs"]:
                                if requirement["library"] == dep and requirement["version"] not in defined:
                                    version_mismatches.append({"from": name, "candidate": path, **requirement})
                        candidates.setdefault(str(resolved), path)
                except FileNotFoundError:
                    continue
                except (OSError, ValueError) as exc:
                    errors.append(path + ": " + str(exc))
            paths = sorted(candidates.values())
            edges[name][dep] = paths
            if not paths:
                unresolved.append({"from": name, "needed": dep, "abi": info["abi"]})
            elif len(paths) > 1:
                ambiguous.append({"from": name, "needed": dep, "candidates": paths})
            queue.extend(p for p in paths if p not in seen and p not in queue)
    resolution = symbol_candidates(seen, edges)
    if resolution["limit_exceeded"]:
        errors.append("Symbol candidate comparison exceeds inspection limit")
    apex = {}
    for name in ("com.android.runtime", "com.android.art"):
        try:
            present = guest_path(root, "/apex/" + name).is_dir()
        except (OSError, ValueError):
            present = False
        apex[name] = {"expanded_tree_present": present}
    return {"schema": "galwear-r800-linker-inventory-v1",
            "status": "CANDIDATES_FOUND_ONLY" if not (errors or unresolved or ambiguous or unsupported_search_paths or soname_mismatches or version_mismatches or unbound_version_needs or unsupported_symbol_objects or resolution["missing_strong"] or resolution["ambiguous"] or resolution["incomplete"]) else "REVIEW_REQUIRED",
            "objects": seen, "missing_candidates": unresolved, "ambiguous_candidates": ambiguous,
            "errors": errors, "unsupported_search_paths": unsupported_search_paths,
            "soname_mismatches": soname_mismatches,
            "version_mismatches": version_mismatches, "unbound_version_needs": unbound_version_needs,
            "unsupported_symbol_objects": unsupported_symbol_objects,
            "dependency_edges": edges, "symbol_candidates": resolution,
            "symbol_resolution_verified": False,
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
