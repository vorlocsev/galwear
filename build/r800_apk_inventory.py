#!/usr/bin/env python3
"""Inventory installed APK versions; evidence only, not a package lock or firmware."""
import argparse
import hashlib
import json
import re
from pathlib import Path

PACKAGE = re.compile(r"[A-Za-z0-9_+.~-]+")
SHA = re.compile(r"[0-9a-f]{40}")
MAX_BYTES = 256 * 1024


def read(path):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_BYTES:
        raise ValueError("Missing, symlinked or oversized input")
    return path.read_text(encoding="utf-8")


def canonical(lines):
    packages = lines.splitlines()
    if not packages or any(not PACKAGE.fullmatch(p) for p in packages):
        raise ValueError("Invalid APK inventory")
    if len(packages) != len(set(packages)):
        raise ValueError("Duplicate APK inventory entry")
    return sorted(packages)


def digest(packages):
    return hashlib.sha256(("\n".join(packages) + "\n").encode()).hexdigest()


def identity(commit, run_id, attempt, replica):
    if not isinstance(commit, str) or not SHA.fullmatch(commit):
        raise ValueError("Invalid commit")
    if type(run_id) is not int or run_id < 1 or type(attempt) is not int or attempt < 1:
        raise ValueError("Invalid run identity")
    if replica not in ("a", "b"):
        raise ValueError("Invalid replica")
    return {"galwear_commit": commit, "run_id": run_id,
            "run_attempt": attempt, "runner_replica": replica}


def snapshot(lines, commit, run_id, attempt, replica):
    packages = canonical(lines)
    return {"schema": "galwear-apk-inventory-v1", **identity(commit, run_id, attempt, replica),
            "packages": packages, "package_versions_sha256": digest(packages),
            "packages_fully_pinned": False, "safe_to_flash": False}


def verify(manifest, image, commit, run_id, attempt, replica):
    if not isinstance(manifest, dict) or not isinstance(image, dict):
        raise ValueError("Expected evidence objects")
    expected = identity(commit, run_id, attempt, replica)
    for evidence in (manifest, image):
        for field, value in expected.items():
            if type(evidence.get(field)) is not type(value) or evidence[field] != value:
                raise ValueError("Wrong build identity: " + field)
        if evidence.get("safe_to_flash") is not False:
            raise ValueError("Invalid safety flag")
    if (manifest.get("schema") != "galwear-apk-inventory-v1" or
            manifest.get("packages_fully_pinned") is not False or
            image.get("schema") != "galwear-r800-image-repeatability-v1" or
            image.get("status") != "ONE_BUILD_EVIDENCE_ONLY"):
        raise ValueError("Unexpected evidence schema/status")
    packages = manifest.get("packages")
    if not isinstance(packages, list) or not all(isinstance(p, str) for p in packages):
        raise ValueError("Invalid package list")
    if canonical("\n".join(packages)) != packages or digest(packages) != manifest.get("package_versions_sha256"):
        raise ValueError("Noncanonical or inconsistent package inventory")
    return packages


def compare(first, second, image_a, image_b, commit, run_id, attempt):
    a = verify(first, image_a, commit, run_id, attempt, "a")
    b = verify(second, image_b, commit, run_id, attempt, "b")
    return {"schema": "galwear-apk-inventory-comparison-v1",
            "status": "APK_VERSIONS_MATCH" if a == b else "REJECT_PACKAGE_DRIFT",
            "only_a": sorted(set(a) - set(b)), "only_b": sorted(set(b) - set(a)),
            "galwear_commit": commit, "run_id": run_id, "run_attempt": attempt,
            "package_versions_match": a == b, "packages_fully_pinned": False,
            "safe_to_flash": False}


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--commit", required=True)
    p.add_argument("--run-id", required=True, type=int)
    p.add_argument("--attempt", required=True, type=int)
    p.add_argument("--output", required=True, type=Path)
    sub = p.add_subparsers(dest="action", required=True)
    s = sub.add_parser("snapshot")
    s.add_argument("--installed", required=True, type=Path)
    s.add_argument("--replica", choices=("a", "b"), required=True)
    c = sub.add_parser("compare")
    for flag in ("first", "second", "image-a", "image-b"):
        c.add_argument("--" + flag, required=True, type=Path)
    args = p.parse_args()
    try:
        if args.action == "snapshot":
            result = snapshot(read(args.installed), args.commit, args.run_id, args.attempt, args.replica)
        else:
            result = compare(*(json.loads(read(x)) for x in
                               (args.first, args.second, args.image_a, args.image_b)),
                             args.commit, args.run_id, args.attempt)
        rc = 2 if result.get("status") == "REJECT_PACKAGE_DRIFT" else 0
    except (OSError, ValueError, TypeError) as exc:
        result = {"status": "REJECT", "reason": str(exc), "safe_to_flash": False}
        rc = 2
    args.output.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(result.get("status", "APK_INVENTORY_RECORDED"))
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
