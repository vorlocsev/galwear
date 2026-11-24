#!/usr/bin/env python3
"""Evidence-only comparison of TWO independent NON-RELEASE SM-R800 builds.

No kernel compilation, network access, image upload, flashing or firmware
distribution. A two-run match is not general proof of reproducible firmware.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
import subprocess
import sys

SCHEMA = "galwear-r800-image-repeatability-v1"
BASE = "50db73fc799f20a7120a8b5f653b16cc123d856f"
SHA256 = re.compile(r"^[0-9a-f]{64}$")
GIT_SHA = re.compile(r"^[0-9a-f]{40}$")
IMAGE_ID = re.compile(r"^sha256:[0-9a-f]{64}$")
COMPARE_FIELDS = (
    "galwear_commit", "source_commit", "container_image_id",
    "compiler", "linker", "image_sha256", "image_bytes",
    "embedded_cpio_sha256", "embedded_init_sha256",
    "kernel_config_sha256", "kernel_patch_sha256",
)
MAX_IMAGE = 256 * 1024 * 1024
MAX_JSON = 64 * 1024


class EvidenceError(ValueError):
    pass


def hash_file(path: Path, limit: int) -> tuple[str, int]:
    if path.is_symlink() or not path.is_file():
        raise EvidenceError("Missing or symlinked build output")
    size = path.stat().st_size
    if not 1 <= size <= limit:
        raise EvidenceError("Build output size outside supported bounds")
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest(), size


def read_json(path: Path) -> dict:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_JSON:
        raise EvidenceError("Evidence JSON is missing, symlinked or oversized")
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise EvidenceError("Expected JSON object")
    return raw


def local_git_commit(source: Path) -> str:
    if not source.is_dir():
        raise EvidenceError("Kernel checkout absent")
    try:
        output = subprocess.run(
            ["git", "-C", str(source), "rev-parse", "HEAD"],
            capture_output=True, text=True, check=False, timeout=10)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise EvidenceError("Cannot read kernel source HEAD") from exc
    if output.returncode or output.stdout.strip() != BASE:
        raise EvidenceError("Kernel checkout is not the pinned source SHA")
    return BASE


def version(binary: str) -> str:
    try:
        result = subprocess.run([binary, "--version"], capture_output=True,
                                text=True, timeout=10, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise EvidenceError("Pinned compiler unavailable") from exc
    if result.returncode:
        raise EvidenceError("Pinned compiler returned failure")
    output = result.stdout + result.stderr
    if not re.search(r"(?<![0-9])19\.1\.4(?![0-9])", output):
        raise EvidenceError("Compiler/linker version is not exactly 19.1.4")
    return "19.1.4"


def emit(*, image: Path, config: Path, patch: Path, init_evidence: Path,
         cpio_evidence: Path, source: Path, run_id: str, attempt: str,
         galwear_commit: str, container_image_id: str) -> dict:
    if not str(run_id).isdigit() or int(run_id) < 1:
        raise EvidenceError("Invalid build run ID")
    if not str(attempt).isdigit() or int(attempt) < 1:
        raise EvidenceError("Invalid build attempt")
    if not GIT_SHA.fullmatch(galwear_commit):
        raise EvidenceError("Invalid Galwear source SHA")
    if not IMAGE_ID.fullmatch(container_image_id):
        raise EvidenceError("Container image identity not recorded")
    source_sha = local_git_commit(source)
    ci = read_json(init_evidence)
    cp = read_json(cpio_evidence)
    if ci.get("status") != "NON_RELEASE_INITRAMFS_SPEC_ONLY":
        raise EvidenceError("Init build is not the expected non-release type")
    if cp.get("status") != "SYNTHETIC_STRUCTURE_PASS_ONLY" or cp.get("embedded_init_exact_match") is not True:
        raise EvidenceError("Embedded CPIO byte comparison was not successful")
    init_sha = ci.get("init", {}).get("sha256")
    if not isinstance(init_sha, str) or not SHA256.fullmatch(init_sha):
        raise EvidenceError("Invalid init digest")
    if cp.get("embedded_init_sha256") != init_sha:
        raise EvidenceError("CPIO embeds a different init ELF")
    cpio_sha = cp.get("archive_sha256")
    if not isinstance(cpio_sha, str) or not SHA256.fullmatch(cpio_sha):
        raise EvidenceError("Invalid embedded CPIO digest")
    image_sha, image_bytes = hash_file(image, MAX_IMAGE)
    config_sha, _ = hash_file(config, 1024 * 1024)
    patch_sha, _ = hash_file(patch, 8 * 1024 * 1024)
    return {
        "schema": SCHEMA,
        "status": "ONE_BUILD_EVIDENCE_ONLY",
        "run_id": int(run_id),
        "run_attempt": int(attempt),
        "galwear_commit": galwear_commit,
        "source_commit": source_sha,
        "container_image_id": container_image_id,
        "compiler": version("clang-19"),
        "linker": version("ld.lld"),
        "image_sha256": image_sha,
        "image_bytes": image_bytes,
        "embedded_cpio_sha256": cpio_sha,
        "embedded_init_sha256": init_sha,
        "kernel_config_sha256": config_sha,
        "kernel_patch_sha256": patch_sha,
        "kernel_compiled": True,
        "cpio_verified": True,
        "kernel_boot_tested": False,
        "reproducibility_proven": False,
        "safe_to_flash": False,
    }


def validate_manifest(obj: dict) -> None:
    if obj.get("schema") != SCHEMA or obj.get("status") != "ONE_BUILD_EVIDENCE_ONLY":
        raise EvidenceError("Invalid or unverified build evidence")
    if type(obj.get("run_id")) is not int or obj["run_id"] < 1:
        raise EvidenceError("Missing run ID")
    if type(obj.get("run_attempt")) is not int or obj["run_attempt"] < 1:
        raise EvidenceError("Missing run attempt")
    if obj.get("source_commit") != BASE or not GIT_SHA.fullmatch(str(obj.get("galwear_commit", ""))):
        raise EvidenceError("Unknown source revision")
    if not IMAGE_ID.fullmatch(str(obj.get("container_image_id", ""))):
        raise EvidenceError("Unknown container identity")
    if obj.get("compiler") != "19.1.4" or obj.get("linker") != "19.1.4":
        raise EvidenceError("Wrong compiler")
    for field in COMPARE_FIELDS:
        if field.endswith("_sha256") and not SHA256.fullmatch(str(obj.get(field, ""))):
            raise EvidenceError("Invalid build digest: " + field)
    if type(obj.get("image_bytes")) is not int or not 1 <= obj["image_bytes"] <= MAX_IMAGE:
        raise EvidenceError("Invalid build image size")
    if (obj.get("kernel_compiled") is not True or obj.get("cpio_verified") is not True
        or obj.get("safe_to_flash") is not False or obj.get("kernel_boot_tested") is not False
        or obj.get("reproducibility_proven") is not False):
        raise EvidenceError("Invalid safety or completion flags")


def compare(first: dict, second: dict) -> dict:
    validate_manifest(first)
    validate_manifest(second)
    if (first["run_id"], first["run_attempt"]) == (second["run_id"], second["run_attempt"]):
        raise EvidenceError("Two independent build attempts are required")
    differences = [name for name in COMPARE_FIELDS if first.get(name) != second.get(name)]
    return {
        "schema": "galwear-r800-image-repeatability-comparison-v1",
        "status": ("TWO_RUN_HASH_MATCH" if not differences else "REJECT_MISMATCH"),
        "first_run_id": first["run_id"],
        "second_run_id": second["run_id"],
        "differences": differences,
        "two_run_byte_identity_observed": not differences,
        "general_reproducibility_proven": False,
        "container_packages_fully_pinned": False,
        "kernel_boot_tested": False,
        "safe_to_flash": False,
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Read-only comparison of non-release build SHA-256 evidence")
    sub = p.add_subparsers(dest="action", required=True)
    a = sub.add_parser("emit")
    for name in ("image", "config", "patch", "init_evidence", "cpio_evidence", "source"):
        a.add_argument("--" + name.replace("_", "-"), required=True, type=Path)
    a.add_argument("--run-id", required=True)
    a.add_argument("--attempt", required=True)
    a.add_argument("--galwear-commit", required=True)
    a.add_argument("--container-image-id", required=True)
    c = sub.add_parser("compare")
    c.add_argument("--first", type=Path, required=True)
    c.add_argument("--second", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args(argv)
    try:
        if args.action == "emit":
            result = emit(image=args.image, config=args.config, patch=args.patch,
                          init_evidence=args.init_evidence, cpio_evidence=args.cpio_evidence,
                          source=args.source, run_id=args.run_id, attempt=args.attempt,
                          galwear_commit=args.galwear_commit,
                          container_image_id=args.container_image_id)
        else:
            result = compare(read_json(args.first), read_json(args.second))
        rc = 0 if result["status"] in ("ONE_BUILD_EVIDENCE_ONLY", "TWO_RUN_HASH_MATCH") else 2
    except (EvidenceError, OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        result = {"schema": SCHEMA, "status": "REJECT", "reason": str(exc),
                  "safe_to_flash": False, "reproducibility_proven": False}
        rc = 2
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n",
                           encoding="utf-8")
    print(result["status"])
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
