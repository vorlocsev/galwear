#!/usr/bin/env python3
"""Non-destructive Exynos 9110 kernel source/patch preflight.

With no --source-tree this checks patch/config metadata only.
With --source-tree, verifies the EXACT kernel base and runs git apply --check.
It NEVER patches sources, compiles code, mounts images or connects to a watch.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys

SCHEMA = "galwear-r800-kernel-preflight-v1"
# Declared in build/mk_kernel_patch.sh (not independently verified upstream).
PINNED_BASE = "50db73fc799f20a7120a8b5f653b16cc123d856f"
ALLOWED_ROOTS = frozenset(
    ("drivers", "include", "kernel", "mm", "scripts", "security", "sound"))
REQUIRED_PATCH_FILES = frozenset((
    "drivers/cpuidle/cpuidle-exynos64.c",
    "drivers/soc/samsung/exynos-pd.c",
    "drivers/soc/samsung/exynos-pm.c",
    "drivers/soc/samsung/exynos-powermode.c",
))
REQUIRED_CONFIG = frozenset((
    "CONFIG_ARM64=y",
    "CONFIG_ARM64_EXYNOS_CPUIDLE=y",
    "CONFIG_SUSPEND=y",
    "CONFIG_PM_DEBUG=y",
    "CONFIG_PM_WAKELOCKS=y",
    "CONFIG_SENSORS_SSP_BBD=y",
))
MAX_PATCH_BYTES = 8 * 1024 * 1024
MAX_CONFIG_BYTES = 512 * 1024


class PreflightError(ValueError):
    pass


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _run_git(root: Path, *args: str) -> str:
    try:
        run = subprocess.run(
            ["git", "-C", str(root), *args],
            capture_output=True, text=True, timeout=45, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise PreflightError(f"Git check unavailable: {type(exc).__name__}") from exc
    if run.returncode:
        # Do not include external paths/usernames from stderr in an exported report.
        raise PreflightError(
            f"Git {args[0]} returned {run.returncode}; review source locally")
    return run.stdout.strip()


def _safe_patch_path(value: str) -> bool:
    parts = PurePosixPath(value).parts
    return (
        value != "" and "\\" not in value and
        not value.startswith("/") and
        len(parts) >= 2 and parts[0] in ALLOWED_ROOTS and
        ".." not in parts and "." not in parts and
        all(part not in ("", ".", "..") for part in value.split("/")))


def inspect_patch(patch_path: Path) -> dict:
    if not patch_path.is_file() or patch_path.is_symlink():
        raise PreflightError("Kernel patch missing or symlinked")
    size = patch_path.stat().st_size
    if not 100 <= size <= MAX_PATCH_BYTES:
        raise PreflightError("Kernel patch size out of bounds")
    data = patch_path.read_text(encoding="utf-8")
    headers = re.findall(r"(?m)^diff --git a/(\S+) b/(\S+)$", data)
    if not headers:
        raise PreflightError("No git diff file headers")
    paths = []
    for old, new in headers:
        if old != new or not _safe_patch_path(new):
            raise PreflightError("Unsafe or renamed kernel patch path")
        paths.append(new)
    if len(set(paths)) != len(paths):
        raise PreflightError("Duplicate file sections in patch")
    missing = REQUIRED_PATCH_FILES - set(paths)
    if missing:
        raise PreflightError("Missing required Exynos power/idle patch files")
    hunks = re.findall(r"(?m)^@@ -\d+(?:,\d+)? \+\d+(?:,\d+)? @@", data)
    if not hunks:
        raise PreflightError("No unified diff hunks in kernel patch")
    return {
        "patch_files": len(paths),
        "patch_hunks": len(hunks),
        "patch_sha256": _sha256(patch_path),
        "patch_bytes": size,
        "exynos_power_files_present": True,
    }


def inspect_config(path: Path) -> dict:
    if not path.is_file() or path.is_symlink():
        raise PreflightError("Kernel configuration missing or symlinked")
    if not 100 <= path.stat().st_size <= MAX_CONFIG_BYTES:
        raise PreflightError("Kernel configuration size out of bounds")
    settings = set(path.read_text(encoding="utf-8").splitlines())
    missing = REQUIRED_CONFIG - settings
    if missing:
        raise PreflightError(
            "Required kernel settings absent: " + ", ".join(sorted(missing)))
    return {
        "required_options_present": True,
        "config_sha256": _sha256(path),
    }


def inspect_tree(source: Path, patch: Path, *, expected_base=PINNED_BASE) -> dict:
    """Verify clean, pinned tree, then git apply --check (no changes)."""
    if not source.is_dir() or not (source / ".git").exists():
        raise PreflightError("No local kernel git worktree was supplied")
    head = _run_git(source, "rev-parse", "HEAD")
    if head != expected_base:
        raise PreflightError("Kernel source SHA differs from pinned baseline")
    if _run_git(source, "status", "--porcelain"):
        raise PreflightError("Kernel worktree is dirty; refuse check")
    before = head
    # Git --check validates both patch context and permissions without applying.
    _run_git(source, "apply", "--check", str(patch.resolve()))
    if _run_git(source, "rev-parse", "HEAD") != before:
        raise PreflightError("Kernel worktree HEAD unexpectedly changed")
    if _run_git(source, "status", "--porcelain"):
        raise PreflightError("Kernel worktree changed during read-only check")
    return {
        "pinned_source_base_sha": expected_base,
        "git_apply_check": "PASS",
        "source_worktree_modified": False,
        "kernel_compiled": False,
    }


def inspect_project(repo: Path, source: Path | None = None) -> dict:
    repo = repo.resolve(strict=True)
    patch = repo / "src/kernel/r800-wearos.patch"
    config = repo / "src/kernel/r800.config"
    dt = repo / "src/dt/r800.dts"
    if not dt.is_file() or dt.is_symlink():
        raise PreflightError("Exynos DT source absent or symlinked")
    if not (100 <= dt.stat().st_size <= 1024 * 1024):
        raise PreflightError("Exynos DT source size out of bounds")
    regen = repo / "build/mk_kernel_patch.sh"
    if not regen.is_file():
        raise PreflightError("Patch-generation script missing")
    script = regen.read_text(encoding="utf-8")
    if f"BASE={PINNED_BASE}" not in script:
        raise PreflightError("Kernel patch-generator base has changed")
    if '"$REPO/src/kernel/r800-wearos.patch"' not in script:
        raise PreflightError("Kernel patch-generator path is not correct")
    result = {
        "schema": SCHEMA,
        "expected_kernel_base": PINNED_BASE,
        "source_tree_available": source is not None,
        "static_patch_audit": inspect_patch(patch),
        "kernel_config_audit": inspect_config(config),
        "device_tree_sha256": _sha256(dt),
        "patch_matches_supplied_kernel_tree": False,
        "kernel_compiled": False,
        "firmware_built": False,
        "safe_to_flash": False,
    }
    if source is None:
        result["status"] = "STATIC_ONLY_SOURCE_NOT_PROVIDED"
    else:
        result["source_audit"] = inspect_tree(source, patch)
        result["patch_matches_supplied_kernel_tree"] = True
        result["status"] = "PATCH_APPLIES_TO_PINNED_SOURCE_ONLY"
    return result


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Check R800 kernel patch/base offline, no source modification")
    parser.add_argument("--repository", type=Path,
                        default=Path(__file__).resolve().parents[1])
    parser.add_argument("--source-tree", type=Path, help="Existing, clean Exynos kernel git checkout")
    parser.add_argument("--report", type=Path, help="Optional JSON output path")
    args = parser.parse_args(argv)
    try:
        result = inspect_project(args.repository, args.source_tree)
        status = 0
    except (PreflightError, OSError, UnicodeError, ValueError) as exc:
        result = {"schema": SCHEMA, "status": "REJECT",
                  "reason": str(exc), "safe_to_flash": False,
                  "kernel_compiled": False}
        status = 2
    if args.report:
        args.report.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n",
                               encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))
    return status


if __name__ == "__main__":
    raise SystemExit(main())
