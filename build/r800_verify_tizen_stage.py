#!/usr/bin/env python3
"""Verify a staged Tizen ELF subset offline; not a runtime or authenticity proof."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat

from r800_android_userspace_preflight import read_regular
from r800_tizen_dependencies import review_loads, MAX_FILE, MAX_TOTAL, MAX_NODES

MANIFEST = "tizen-elf-evidence.json"
MAX_MANIFEST = 2 * 1024**2
MAX_ENTRIES = MAX_NODES * 2
MAX_TREE_ITEMS = MAX_ENTRIES * 32 + 1
FALSE_FLAGS = ("configuration_complete", "plugins_complete", "ownership_preserved",
               "runtime_verified", "safe_to_flash")


def unique_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate manifest key")
        result[key] = value
    return result


def guest_name(name):
    if (not isinstance(name, str) or not name.startswith(("/usr/bin/", "/bin/", "/usr/lib/", "/lib/"))
            or len(name) > 1024 or any(not re.fullmatch(r"[A-Za-z0-9_.+-]+", p)
                                       or p in (".", "..") for p in name[1:].split("/"))
            or len(name[1:].split("/")) > 32):
        raise ValueError("Invalid manifest guest path")
    return PurePosixPath(name).relative_to("/").as_posix()


def verify(root, *, expected=None):
    """Inspect a quiescent local tree; expected binds it to a trusted staging result."""
    root = Path(root)
    if not stat.S_ISDIR(root.lstat().st_mode):
        raise ValueError("Expected real staging directory")
    manifest = root / MANIFEST
    if manifest.lstat().st_nlink != 1:
        raise ValueError("Manifest hard link not allowed")
    report = json.loads(read_regular(manifest, MAX_MANIFEST), object_pairs_hook=unique_keys)
    if (not isinstance(report, dict) or report.get("status") != "TIZEN_ELF_SUBSET_ONLY"
            or report.get("strict_4k_page_review") is not True
            or any(report.get(flag) is not False for flag in FALSE_FLAGS)
            or type(report.get("version_records_checked")) is not int
            or report["version_records_checked"] < 0):
        raise ValueError("Invalid staging manifest")
    if expected is not None and report != expected:
        raise ValueError("Manifest differs from trusted staging result")
    files = report.get("files")
    if not isinstance(files, dict) or not 1 <= len(files) <= MAX_ENTRIES:
        raise ValueError("Invalid manifest file count")
    wanted = {MANIFEST}
    dirs = set()
    for guest, row in files.items():
        relative = guest_name(guest)
        wanted.add(relative)
        dirs.update(p.as_posix() for p in PurePosixPath(relative).parents if p.as_posix() != ".")
        if not isinstance(row, dict):
            raise ValueError("Invalid manifest file record")
        source = row.get("source")
        guest_name(source)
        if source not in files:
            raise ValueError("Missing canonical source in manifest")
        if (type(row.get("bytes")) is not int or not 0 < row["bytes"] <= MAX_FILE
                or not isinstance(row.get("sha256"), str)
                or not re.fullmatch(r"[a-f0-9]{64}", row["sha256"])
                or row.get("mode") not in ("0o644", "0o755")):
            raise ValueError("Invalid manifest file metadata")
    seen = set()
    seen_dirs = set()
    pending = [root]
    items = 0
    while pending:
        parent = pending.pop()
        with os.scandir(parent) as entries:
            for entry in entries:
                items += 1
                if items > MAX_TREE_ITEMS:
                    raise ValueError("Staging tree exceeds entry budget")
                path = Path(entry.path)
                relative = path.relative_to(root).as_posix()
                info = entry.stat(follow_symlinks=False)
                if stat.S_ISDIR(info.st_mode):
                    if relative not in dirs or info.st_mode & 0o7000:
                        raise ValueError("Unexpected directory or privileged mode: " + relative)
                    seen_dirs.add(relative)
                    pending.append(path)
                elif stat.S_ISREG(info.st_mode):
                    if relative not in wanted or info.st_nlink != 1 or info.st_mode & 0o7000:
                        raise ValueError("Unexpected file, hard link or privileged mode: " + relative)
                    seen.add(relative)
                else:
                    raise ValueError("Nonregular staging entry: " + relative)
    if seen != wanted or seen_dirs != dirs:
        raise ValueError("Staging tree does not match manifest")
    total = 0
    for guest, row in sorted(files.items()):
        path = root / guest_name(guest)
        info = path.lstat()
        if info.st_nlink != 1 or oct(stat.S_IMODE(info.st_mode)) != row["mode"]:
            raise ValueError("Staged file mode or link count mismatch: " + guest)
        raw = read_regular(path, MAX_FILE)
        total += len(raw)
        if total > MAX_TOTAL:
            raise ValueError("Staged file byte budget exceeded")
        if len(raw) != row["bytes"] or hashlib.sha256(raw).hexdigest() != row["sha256"]:
            raise ValueError("Staged file digest mismatch: " + guest)
        if review_loads(raw, strict_pages=True) != row.get("load_review"):
            raise ValueError("Staged load review mismatch: " + guest)
        canonical = files[row["source"]]
        if (not isinstance(canonical, dict) or canonical.get("source") != row["source"]
                or any(canonical.get(k) != row.get(k) for k in ("bytes", "sha256", "load_review"))):
            raise ValueError("Staged alias evidence mismatch: " + guest)
    return {"status": "TIZEN_STAGED_TREE_STATIC_ONLY", "file_count": len(files),
            "bytes": total, "manifest_matches_expected": expected is not None,
            "strict_4k_page_review": True, "runtime_verified": False, "safe_to_flash": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path)
    args = parser.parse_args()
    try:
        report = verify(args.root)
    except (OSError, ValueError, RecursionError) as exc:
        report = {"status": "REVIEW_REQUIRED", "error": str(exc), "safe_to_flash": False}
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["status"] == "TIZEN_STAGED_TREE_STATIC_ONLY" else 2


if __name__ == "__main__":
    raise SystemExit(main())
