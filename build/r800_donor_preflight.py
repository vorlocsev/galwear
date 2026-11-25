#!/usr/bin/env python3
"""Read-only local donor input acceptance; never mounts, extracts or builds images."""
from __future__ import annotations
import argparse
import hashlib
import json
import re
import stat
import sys
from pathlib import Path

from r800_android_userspace_preflight import read_regular
from r800_boot_candidate import inspect_template, PARTITION
from r800_vendor_inputs import image_info, file_info
from r800_stage_components import dex, static_arm
from r800_payload_candidate import ASSET_SIZES, RADIO_FILES, BINS, DIRS

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "installer"))
from r800_build_provenance import validate_combination

MAX_DONOR = 4 * 1024**3
MAX_FILE = 64 * 1024**2

def checked(root, name):
    path = root / name
    if path.resolve(strict=False) != path:
        raise ValueError("Symlink in input path")
    return path

def digest(path, maximum=MAX_DONOR):
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= maximum:
        raise ValueError("Expected nonempty bounded regular file")
    h = hashlib.sha256()
    count = 0
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024*1024), b""):
            count += len(block)
            if count > before.st_size:
                raise ValueError("Input grew during read")
            h.update(block)
    after = path.stat()
    if count != before.st_size or (before.st_size, before.st_mtime_ns, before.st_ino) != (after.st_size, after.st_mtime_ns, after.st_ino):
        raise ValueError("Input changed during read")
    return {"bytes": count, "sha256": h.hexdigest()}

def boot(path):
    raw = read_regular(path, PARTITION)
    _, _, _, _, ids = inspect_template(raw)
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
            "exyn_entries": len(ids), "signature_verified": False}

def combo(path):
    before = digest(path)
    report = validate_combination(path)
    if digest(path) != before:
        raise ValueError("Combination changed during validation")
    return {**before, **report}

def system(path):
    info = digest(path)
    with path.open("rb") as f:
        header = f.read(1082)
    if path.suffix == ".sqfs":
        if header[:4] != b"hsqs":
            raise ValueError("Expected SquashFS magic")
    elif header[1080:1082] != b"\x53\xef":
        raise ValueError("Expected ext4 magic")
    return info

def sized(path, size):
    info = digest(path, size)
    if info["bytes"] != size:
        raise ValueError("Wrong display asset size")
    return info

def verify_components(root, expected_sha):
    manifest = json.loads(read_regular(checked(root, "component-evidence.json"), 1024*1024))
    if (manifest["status"] != "PARTIAL_COMPILED_COMPONENTS_ONLY"
            or manifest["source_sha"] != expected_sha or manifest["safe_to_flash"] is not False):
        raise ValueError("Component evidence status or source SHA mismatch")
    files = manifest["files"]
    if not isinstance(files, dict) or not 1 <= len(files) <= 128:
        raise ValueError("Invalid component manifest file count")
    actual = set()
    for item in root.rglob("*"):
        if item.is_symlink():
            raise ValueError("Symlink in compiled component tree")
        if item.is_file():
            actual.add(item.relative_to(root).as_posix())
        elif not item.is_dir():
            raise ValueError("Special file in compiled component tree")
    if actual != set(files) | {"component-evidence.json"}:
        raise ValueError("Component manifest inventory mismatch")
    for name, info in files.items():
        p = checked(root, name)
        if not p.is_relative_to(root):
            raise ValueError("Component outside tree")
        observed = digest(p, MAX_FILE)
        if observed != {"bytes": info["bytes"], "sha256": info["sha256"]}:
            raise ValueError("Component hash mismatch: " + name)
        if oct(stat.S_IMODE(p.stat().st_mode)) != info["mode"]:
            raise ValueError("Component mode mismatch: " + name)
    return {"source_sha": expected_sha, "files": len(files)}

def audit(donors, components, expected_sha):
    if not re.fullmatch(r"[0-9a-f]{40}", expected_sha):
        raise ValueError("Expected full source commit SHA")
    donors, components = donors.resolve(), components.resolve()
    rows = {}
    def check(name, fn, root=donors):
        try:
            rows[name] = {"status": "STRUCTURE_PASS_ONLY", **fn(checked(root, name))}
        except FileNotFoundError:
            rows[name] = {"status": "MISSING"}
        except (OSError, ValueError, KeyError, TypeError, RuntimeError) as exc:
            rows[name] = {"status": "REJECTED", "reason": str(exc)}
    try:
        rows["compiled-components"] = {"status": "STRUCTURE_PASS_ONLY",
                                      **verify_components(components, expected_sha)}
    except (OSError, ValueError, KeyError, TypeError, RuntimeError) as exc:
        rows["compiled-components"] = {"status": "REJECTED", "reason": str(exc)}
    check("samsung/combination.tar.md5", combo)
    check("samsung/boot-template.img", boot)
    check("android/base-vendor.img", image_info)
    check("android/j4-vendor.img", image_info)
    check("android/libeffectsconfig.so", lambda p: file_info(p, True))
    systems = [n for n in ("android/system.img", "android/system.sqfs") if (donors/n).exists() or (donors/n).is_symlink()]
    if len(systems) != 1:
        rows["android/system"] = {"status": "MISSING" if not systems else "REJECTED",
                                  "reason": "Supply exactly one raw ext4 or SquashFS system image"}
    else:
        check(systems[0], system)
    for lib in ("libc.so.6", "libdl.so.2", "libpthread.so.0"):
        check("tizen/" + lib, lambda p: file_info(p, True))
    for name in RADIO_FILES:
        if name not in ("fw/bt/libbt-vendor.so", "fw/bt/bt_vendor.conf"):
            check("payload/" + name, lambda p: digest(p, MAX_FILE))
    for name, size in ASSET_SIZES.items():
        check("payload/" + name, lambda p, size=size: sized(p, size))
    for name in ("busybox", "busybox-extras", "fsfreeze"):
        def tool(p):
            info = digest(p, MAX_FILE)
            if not p.stat().st_mode & 0o111:
                raise ValueError("Missing executable mode")
            raw = read_regular(p, MAX_FILE)
            if raw[:5] != b"\x7fELF\x02":
                static_arm(raw)
            else:
                # AArch64 donor utilities are separately inspected by userspace checks.
                info["arm64_runtime_unverified"] = True
            return info
        check("payload/bin/" + name, tool)
    for name in ("root", "tzlite", "lib"):
        def directory(p):
            if not p.is_dir() or not any(p.iterdir()):
                raise ValueError("Expected nonempty curated directory")
            return {"contents_verified": False}
        check("payload/" + name, directory)
    blockers = [name for name, row in rows.items() if row["status"] != "STRUCTURE_PASS_ONLY"]
    return {"status": "DONOR_INPUTS_INCOMPLETE" if blockers else "DONOR_INPUTS_STRUCTURE_ONLY",
            "inputs": rows, "blockers": blockers, "donor_authenticity_verified": False,
            "hidl_dependency_closure_verified": False, "persistent_input_verified": False,
            "pit_verified": False, "runtime_verified": False, "safe_to_flash": False}

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--donors", required=True, type=Path)
    p.add_argument("--components", required=True, type=Path)
    p.add_argument("--source-sha", required=True)
    args = p.parse_args()
    result = audit(args.donors, args.components, args.source_sha)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 2 if result["blockers"] else 0

if __name__ == "__main__":
    sys.exit(main())
