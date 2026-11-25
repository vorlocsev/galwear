#!/usr/bin/env python3
"""Package audited staged init files for a RAM-only virt preflight, not Android boot."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

from r800_android_init_rootfs import CONFIG, unique_object
from r800_android_init_dependencies import regular
from r800_android_dynamic_audit import inspect_elf, RUNTIME, MAX_ELF
from r800_initramfs_spec import validate_init

CAP = 64 * 1024 * 1024
MAX_FILES = 256
BIN = re.compile(r"system/bin/(?:bootstrap/)?(?:init|galwear_property_service|galwear_property_client|linker64)")
LIB = re.compile(r"(?:system/lib64/(?:bootstrap/)?|apex/com\.android\.runtime/lib64/bionic/)[A-Za-z0-9_.+-]+\.so")
LINKER = RUNTIME + "/bin/linker64"
CONTEXTS = (
    "system/etc/selinux/plat_property_contexts",
    "system_ext/etc/selinux/system_ext_property_contexts",
    "vendor/etc/selinux/vendor_property_contexts",
    "vendor/etc/selinux/nonplat_property_contexts",
    "product/etc/selinux/product_property_contexts",
    "odm/etc/selinux/odm_property_contexts",
)

def sha(data):
    return hashlib.sha256(data).hexdigest()

def snapshot(path, limit):
    if path is None or path.is_symlink() or not path.is_file():
        raise ValueError("Missing or symlinked file")
    with path.open("rb") as f:
        data = f.read(limit + 1)
    if not 0 < len(data) <= limit:
        raise ValueError("File size outside bounds")
    return data

def prepare_entries(staged, product, init, readelf="readelf"):
    staged = staged.resolve(strict=True)
    product = product.resolve(strict=True)
    layout = json.loads(snapshot(regular(staged, "guest-layout.json"), 262144),
                        object_pairs_hook=unique_object)
    if (layout.get("status") != "INIT_EXPERIMENTAL_ROOTFS_STAGED_ONLY"
            or layout.get("safe_to_flash") is not False):
        raise ValueError("Staged diagnostic rootfs required")
    files = layout["files"]
    if not isinstance(files, dict) or not 1 <= len(files) <= MAX_FILES:
        raise ValueError("Invalid staged file count")
    entries = {}
    metadata = {}
    total = 0

    def add(name, mode, data, major=0, minor=0):
        nonlocal total
        if name in entries:
            raise ValueError("Duplicate guest entry: " + name)
        total += len(data)
        if total > CAP:
            raise ValueError("Archive payload exceeds RAM budget")
        entries[name] = (mode, data, major, minor)

    for rel, info in sorted(files.items()):
        is_bin = bool(BIN.fullmatch(rel) or rel == LINKER)
        if not is_bin and not LIB.fullmatch(rel):
            raise ValueError("Unexpected staged path: " + rel)
        p = regular(staged, rel)
        data = snapshot(p, MAX_ELF)
        if sha(data) != info["sha256"] or len(data) != info["size_bytes"]:
            raise ValueError("Staged file identity mismatch: " + rel)
        elf = inspect_elf(p, readelf)
        if elf["sha256"] != sha(data) or elf["elf_type"] != 3:
            raise ValueError("Staged ELF identity mismatch: " + rel)
        if not is_bin and (elf["soname"] != Path(rel).name or elf["interpreter"] is not None):
            raise ValueError("Unexpected library metadata: " + rel)
        metadata[rel] = elf
        add(rel, 0o100755 if is_bin else 0o100644, data)
    for name in ("galwear_property_service", "galwear_property_client"):
        if "system/bin/" + name not in metadata:
            raise ValueError("Required service/client missing")
    if not any(p in metadata for p in ("system/bin/init", "system/bin/bootstrap/init")):
        raise ValueError("Original init missing")
    aliases = layout["interpreter_aliases"]
    for rel, target in aliases.items():
        if (rel != "system/bin/linker64" or target not in ("/" + LINKER, "/system/bin/bootstrap/linker64")
                or target[1:] not in metadata):
            raise ValueError("Invalid guest linker alias")
        add(rel, 0o120777, target.encode("ascii"))
    for rel, elf in metadata.items():
        if BIN.fullmatch(rel) and not rel.endswith("/linker64"):
            interp = elf["interpreter"]
            if interp not in ("/system/bin/linker64", "/system/bin/bootstrap/linker64") or interp[1:] not in entries:
                raise ValueError("Missing executable interpreter: " + rel)
        elif rel.endswith("/linker64") and (elf["interpreter"] is not None or elf["needed"]):
            raise ValueError("Unexpected linker metadata")
        for needed in elf["needed"]:
            matches = [p for p in metadata if LIB.fullmatch(p) and Path(p).name == needed]
            if len(matches) != 1:
                raise ValueError("Missing or ambiguous staged dependency: " + needed)
    config = snapshot(regular(staged, "linkerconfig/ld.config.txt"), 65536)
    if config != CONFIG or sha(config) != layout["linkerconfig_sha256"]:
        raise ValueError("Experimental linker config changed")
    add("linkerconfig/ld.config.txt", 0o100644, config)
    context_hashes = {}
    for rel in CONTEXTS:
        path = regular(product, rel)
        if path is None:
            if rel == CONTEXTS[0]:
                raise ValueError("Platform property contexts missing")
            continue
        blob = snapshot(path, 1024 * 1024)
        blob.decode("utf-8", errors="strict")
        if b"\0" in blob:
            raise ValueError("Invalid property context text")
        add(rel, 0o100644, blob)
        context_hashes[rel] = sha(blob)
    init_info = validate_init(init)
    data = snapshot(init, 2 * 1024 * 1024)
    if sha(data) != init_info["sha256"]:
        raise ValueError("Diagnostic init changed")
    add("init", 0o100755, data)
    add("dev/console", 0o020600, b"", 5, 1)
    dirs = {"dev", "proc", "sys", "data"}
    for name in entries:
        dirs.update(str(p) for p in Path(name).parents if str(p) != ".")
    if dirs & set(entries):
        raise ValueError("Directory collision")
    ordered = [(name, (0o040755, b"", 0, 0)) for name in sorted(dirs, key=lambda n: (n.count("/"), n))]
    ordered += sorted(entries.items())
    return ordered, {
        "status": "ANDROID_ROOTFS_PREFLIGHT_ARCHIVE_ONLY",
        "entries": len(ordered), "init_sha256": init_info["sha256"],
        "property_contexts_sha256": context_hashes,
        "elf_metadata": metadata,
        "selected_libraries": layout["selected_libraries"],
        "guest_files": {name: {"mode": item[0], "sha256": sha(item[1])}
                        for name, item in ordered if item[0] & 0o170000 != 0o040000},
        "android_init_started": False, "property_service_started": False,
        "selinux_policy_loaded": False, "safe_to_flash": False,
    }

def prepare(staged, product, init, readelf="readelf"):
    entries, report = prepare_entries(staged, product, init, readelf)
    archive = newc(entries)
    return archive, {**report, "archive_sha256": sha(archive), "archive_bytes": len(archive)}


def newc(entries):
    out = bytearray()
    for ino, (name, (mode, data, major, minor)) in enumerate(
            entries + [("TRAILER!!!", (0, b"", 0, 0))], 1):
        key = name.encode("ascii") + b"\0"
        fields = (ino, mode, 0, 0, 2 if mode & 0o170000 == 0o040000 else 1,
                  0, len(data), 0, 0, major, minor, len(key), 0)
        out.extend(b"070701" + b"".join(f"{n:08x}".encode() for n in fields))
        out.extend(key)
        out.extend(bytes((-len(out)) % 4))
        out.extend(data)
        out.extend(bytes((-len(out)) % 4))
        if len(out) > CAP:
            raise ValueError("Archive exceeds RAM budget")
    return bytes(out)

def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ("staged", "product-out", "init", "archive", "report"):
        p.add_argument("--" + name, type=Path, required=True)
    p.add_argument("--readelf", default="readelf")
    p.add_argument("--verify", action="store_true")
    a = p.parse_args()
    try:
        raw, report = prepare(a.staged, a.product_out, a.init, a.readelf)
        if a.verify:
            if snapshot(a.archive, CAP) != raw:
                raise ValueError("Archive differs from exact canonical reconstruction")
            report["canonical_archive_verified"] = True
        else:
            with a.archive.open("xb") as f:
                f.write(raw)
        rc = 0
    except (OSError, ValueError, TypeError, KeyError, RuntimeError, subprocess.SubprocessError) as exc:
        report = {"status": "REJECT", "reason": str(exc), "safe_to_flash": False}
        rc = 2
    a.report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(report["status"])
    return rc

if __name__ == "__main__":
    raise SystemExit(main())
