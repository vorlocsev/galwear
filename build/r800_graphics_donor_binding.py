#!/usr/bin/env python3
"""Bind a read-only extracted donor tree audit to a clean Git checkout.

Fingerprints are reproducibility evidence, not signed image authenticity or
protection against a malicious concurrent writer. Never execute guest files.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess

from r800_android_linker_audit import audit_graphics_dependencies
from r800_android_userspace_preflight import read_regular, parse_kernel_config, MAX_CONFIG
from r800_display_inventory import MAX_DTB

ROOT = Path(__file__).resolve().parents[1]
MAX_ENTRIES = 250000
MAX_BYTES = 32 * 1024**3
CHUNK = 1024 * 1024


def identity(st):
    return (st.st_dev, st.st_ino, st.st_mode, st.st_size, st.st_mtime_ns, st.st_ctime_ns)


def file_digest(dirfd, name, initial, remaining):
    if initial.st_size > remaining:
        raise ValueError("Donor byte budget exceeded")
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dirfd)
    try:
        if identity(os.fstat(fd)) != identity(initial):
            raise ValueError("Donor file changed before hashing")
        h = hashlib.sha256()
        count = 0
        while True:
            chunk = os.read(fd, CHUNK)
            if not chunk:
                break
            count += len(chunk)
            if count > remaining or count > initial.st_size:
                raise ValueError("Donor file grew or byte budget exceeded")
            h.update(chunk)
        if count != initial.st_size or identity(os.fstat(fd)) != identity(initial):
            raise ValueError("Donor file changed during hashing")
        return h.hexdigest(), count
    finally:
        os.close(fd)


def snapshot(root):
    root = Path(root).resolve(strict=True)
    if not root.is_dir():
        raise ValueError("Expected extracted donor root")
    digest = hashlib.sha256()
    count = total = 0

    def fail(exc):
        raise exc

    for directory, dirs, files, dirfd in os.fwalk(root, follow_symlinks=False, onerror=fail):
        dirs.sort()
        for name in sorted(dirs + files):
            count += 1
            if count > MAX_ENTRIES:
                raise ValueError("Donor entry budget exceeded")
            relative = (Path(directory) / name).relative_to(root).as_posix()
            st = os.stat(name, dir_fd=dirfd, follow_symlinks=False)
            record = [relative, st.st_mode, st.st_uid, st.st_gid]
            if stat.S_ISLNK(st.st_mode):
                record += ["symlink", os.readlink(name, dir_fd=dirfd)]
            elif stat.S_ISREG(st.st_mode):
                value, size = file_digest(dirfd, name, st, MAX_BYTES - total)
                total += size
                record += ["file", size, value]
            elif stat.S_ISDIR(st.st_mode):
                record += ["directory"]
            elif stat.S_ISCHR(st.st_mode) or stat.S_ISBLK(st.st_mode):
                record += ["device", os.major(st.st_rdev), os.minor(st.st_rdev)]
            else:
                raise ValueError("Unsupported special donor entry: " + relative)
            if identity(os.stat(name, dir_fd=dirfd, follow_symlinks=False)) != identity(st):
                raise ValueError("Donor entry changed during hashing")
            digest.update(json.dumps(record, ensure_ascii=True, separators=(",", ":")).encode("ascii") + b"\n")
    return {"algorithm": "sha256-ordered-tree-records-v1", "sha256": digest.hexdigest(),
            "entries": count, "regular_bytes": total}


def checkout_sha(expected):
    if not re.fullmatch(r"[0-9a-f]{40}", expected):
        raise ValueError("Expected full source SHA")
    actual = subprocess.check_output(["git", "-C", str(ROOT), "rev-parse", "HEAD"], text=True).strip()
    dirty = subprocess.check_output(["git", "-C", str(ROOT), "status", "--porcelain",
                                     "--untracked-files=no"], text=True)
    if actual != expected or dirty:
        raise ValueError("Expected clean tracked checkout at exact source SHA")
    return actual


def bound_audit(root, source_sha, config=None, dtb=None):
    checkout_sha(source_sha)
    before = snapshot(root)
    config_raw = read_regular(config, MAX_CONFIG) if config is not None else None
    dtb_raw = read_regular(dtb, MAX_DTB) if dtb is not None else None
    result = audit_graphics_dependencies(
        root, parse_kernel_config(config_raw) if config_raw is not None else None, dtb_raw)
    after = snapshot(root)
    checkout_sha(source_sha)
    if before != after:
        raise ValueError("Extracted donor tree changed during audit")
    for path, raw, limit in ((config, config_raw, MAX_CONFIG), (dtb, dtb_raw, MAX_DTB)):
        if path is not None and read_regular(path, limit) != raw:
            raise ValueError("Kernel input changed during audit")
    result["source_sha"] = source_sha
    result["donor_binding"] = {
        "schema": "galwear-r800-extracted-donor-binding-v1",
        "source_sha": source_sha, "tree_before": before, "tree_after": after,
        "config_sha256": hashlib.sha256(config_raw).hexdigest() if config_raw is not None else None,
        "dtb_sha256": hashlib.sha256(dtb_raw).hexdigest() if dtb_raw is not None else None,
        "tracked_checkout_clean": True, "tree_unchanged_observed": True,
        "original_image_authenticity_verified": False,
        "extraction_provenance_verified": False, "runtime_verified": False,
        "safe_to_flash": False,
    }
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--root", type=Path, required=True)
    p.add_argument("--source-sha", required=True)
    p.add_argument("--config", type=Path)
    p.add_argument("--dtb", type=Path)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    if a.output.resolve().is_relative_to(a.root.resolve()) or a.output.resolve().is_relative_to(ROOT):
        p.error("Output must be outside guest root and source checkout")
    result = bound_audit(a.root, a.source_sha, a.config, a.dtb)
    with a.output.open("x", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2, sort_keys=True)
        stream.write("\n")
    print(result["donor_preflight"]["status"])
    return 0 if result["donor_preflight"]["status"] == "STATIC_DONOR_PREREQUISITES_ONLY" else 2


if __name__ == "__main__":
    raise SystemExit(main())
