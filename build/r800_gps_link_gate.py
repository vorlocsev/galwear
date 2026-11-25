#!/usr/bin/env python3
"""Static link gate for the R800 ARM32 GPS bridge; never runs donor code."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct

from r800_android_linker_audit import inspect
from r800_android_userspace_preflight import read_regular
from r800_tizen_dependencies import interpreter

LIBS = ("libc.so.6", "libdl.so.2", "libpthread.so.0")
LOADER = "ld-linux.so.3"
DONORS = LIBS + (LOADER,)
LIMIT = 64 * 1024**2
MAX_GLIBC = (2, 24, 0)


def check_version(version):
    m = re.fullmatch(r"GLIBC_([0-9]{1,3})\.([0-9]{1,3})(?:\.([0-9]{1,3}))?", version)
    return bool(m and tuple(int(x or 0) for x in m.groups()) <= MAX_GLIBC)


def elf(raw, executable=False):
    info = inspect(raw)
    if info["abi"] != "arm":
        raise ValueError("Expected ARM32")
    flags = struct.unpack_from("<I", raw, 36)[0]
    if flags & 0xff000000 != 0x05000000 or flags & 0x400:
        raise ValueError("Expected ARM EABI5 without hard-float flag")
    if not info["has_dynamic"] or info["elf_type"] != ("ET_EXEC" if executable else "ET_DYN"):
        raise ValueError("Unexpected ELF type or missing dynamic table")
    if info["dynamic_symbol_count"] is None or info["unsupported_symbols"]:
        raise ValueError("Incomplete symbol inventory")
    if executable:
        if interpreter(raw) != "/lib/ld-linux.so.3":
            raise ValueError("Missing expected PT_INTERP")
        if info["custom_search_path"]:
            raise ValueError("Unexpected RPATH/RUNPATH")
        rel = info["relocations"]
        if (rel["unsupported_types"] or rel["packed_tags"] or rel["nonwritable_targets"]
                or not rel["symbol_indices_checked"] or not rel["tls_symbol_types_checked"]):
            raise ValueError("Relocations require review")
    # Packed Android relocations and RELR are not understood by glibc 2.24.
    if info["relocations"]["packed_tags"]:
        raise ValueError("Unsupported packed relocation encoding")
    # DT_RELR and Android packed RELR are not supported by glibc 2.24.
    phoff = struct.unpack_from("<I", raw, 28)[0]
    count = struct.unpack_from("<H", raw, 44)[0]
    for i in range(count):
        typ, off, _, _, size, _, _, _ = struct.unpack_from("<8I", raw, phoff + i*32)
        if typ != 2:
            continue
        for pos in range(off, off + size, 8):
            tag, _ = struct.unpack_from("<iI", raw, pos)
            if tag == 0:
                break
            if tag in (0x6000000f, 0x60000010, 0x60000011, 0x60000012):
                raise ValueError("Unsupported APS2 dynamic tag")
            if tag in (35, 36, 37, 0x6fffe000, 0x6fffe001, 0x6fffe003):
                raise ValueError("Unsupported RELR dynamic tag")
    return info


def compatible_type(required, provided):
    # STT_NOTYPE is unspecified; TLS must always match TLS.
    if required == 6 or provided == 6:
        return required == provided
    if required == 0 or provided == 0:
        return True
    # GNU IFUNC is a callable resolver, not a data export.
    if required in (2, 10) and provided in (2, 10):
        return True
    return required == provided


def import_problems(info, providers, internal=False, scope=None):
    problems = []
    scope = info["needed"] if scope is None else scope
    index = {}
    for name in scope:
        for exp in providers.get(name, {}).get("symbol_exports", []):
            index.setdefault(exp["name"], []).append((name, exp))
    for name in info["needed"]:
        if name not in providers:
            problems.append("Unexpected DT_NEEDED: " + name)
    for need in info["version_needs"]:
        name, version = need["library"], need["version"]
        if name not in info["needed"] or not (check_version(version) or (internal and version == "GLIBC_PRIVATE")):
            problems.append("Unsupported version requirement: " + name + ":" + version)
        elif version not in {v["version"] for v in providers.get(name, {}).get(
                "version_definitions", []) if not v["base"]}:
            problems.append("Version absent from supplied library: " + name + ":" + version)
    declared_versions = {(v["library"], v["version"]) for v in info["version_needs"]}
    for imp in info["symbol_imports"]:
        library, version = imp["version_library"], imp["version"]
        if ((library is None) != (version is None) or
                (library is not None and (library not in info["needed"] or
                                          (library, version) not in declared_versions))):
            problems.append("Unbound symbol version requirement: " + imp["name"])
            continue
        names = {imp["version_library"]} if imp["version_library"] else set(scope)
        if imp["version"] is not None and not (check_version(imp["version"]) or
                (internal and imp["version"] == "GLIBC_PRIVATE")):
            problems.append("Unsupported symbol version: " + imp["name"])
            continue
        matches = [exp for name, exp in index.get(imp["name"], [])
                   if name in names
                   and compatible_type(imp["type"], exp["type"])
                   and (exp["version"] == imp["version"] if imp["version"] is not None
                        else not exp["version_hidden"])]
        if not matches and not imp["weak"]:
            problems.append("No supplied direct provider for: " + imp["name"])
    return problems


def audit(binary, libdir):
    raw = read_regular(binary, LIMIT)
    info = elf(raw, executable=True)
    providers, hashes = {}, {}
    for name in DONORS:
        data = read_regular(libdir / name, LIMIT)
        p = elf(data)
        if p["soname"] != name:
            raise ValueError("Unexpected donor SONAME: " + name)
        if p["custom_search_path"]:
            raise ValueError("Unexpected donor RPATH/RUNPATH: " + name)
        if name == LOADER and interpreter(data) is not None:
            raise ValueError("Loader must not have PT_INTERP")
        providers[name] = p
        hashes[name] = hashlib.sha256(data).hexdigest()
    problems = import_problems(info, providers)
    # glibc components can use GLIBC_PRIVATE internally. Presence of the
    # version/symbol does not establish matching private data layouts.
    for name, obj in providers.items():
        problems.extend(name + ": " + issue for issue in
                        import_problems(obj, providers, internal=True, scope=DONORS))
    edges = {name: obj["needed"] for name, obj in providers.items()}
    edges["gpsbridge"] = info["needed"] + [LOADER]
    return {"status":"REVIEW_REQUIRED" if problems else "STATIC_GLIBC_CLOSURE_ONLY",
            "problems":problems,"sha256":hashlib.sha256(raw).hexdigest(),
            "donor_sha256":hashes,"needed":info["needed"],
            "version_needs":info["version_needs"],"imports_checked":len(info["symbol_imports"]),
            "glibc_ceiling":"2.24","loader_sha256":hashes[LOADER],"dependency_edges":edges,
            "static_closure_pass":not problems,"loader_verified":False,
            "transitive_dependencies_verified":False,"private_abi_verified":False,
            "runtime_verified":False,"safe_to_flash":False}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--binary",type=Path,required=True)
    p.add_argument("--libdir",type=Path,required=True)
    a = p.parse_args()
    try:
        report = audit(a.binary,a.libdir)
    except (OSError,ValueError,struct.error) as exc:
        report = {"status":"REVIEW_REQUIRED","problems":[str(exc)],"safe_to_flash":False}
    print(json.dumps(report,indent=2,sort_keys=True))
    return 2 if report["problems"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
