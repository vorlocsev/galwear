#!/usr/bin/env python3
"""Fail-closed temporary Kconfig override for an embedded R800 smoke initramfs.

Only operates on an *existing disposable* kernel O= output configuration.
Does not modify src/kernel/r800.config, the external source repository, or
any device. Never authorizes flashing; original experimental init mounts data
read-write and remains UNTESTED on physical SM-R800.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

from r800_initramfs_spec import validate_init

SOURCE_LINE = 'CONFIG_INITRAMFS_SOURCE="/root/initramfs/list.txt"'
STATIC_ENTRIES = (
    "dir /dev 0755 0 0",
    "nod /dev/console 0600 0 0 c 5 1",
    "dir /proc 0555 0 0",
    "dir /sys 0555 0 0",
    "dir /data 0755 0 0",
)


class EmbedError(ValueError):
    pass


def require_regular(path: Path, label: str) -> None:
    if path.is_symlink() or not path.is_file():
        raise EmbedError(f"Missing or symlinked {label}")


def prepare_config(config: Path, spec: Path) -> dict:
    require_regular(config, "temporary kernel configuration")
    require_regular(spec, "generated initramfs list")
    # initramfs.spec is generated inside the same disposable directory as
    # the ELF and its evidence. Whitespace/quotes would break Kconfig or
    # gen_init_cpio syntax and must fail closed.
    full_list = str(spec.resolve(strict=True))
    if any(c.isspace() for c in full_list) or any(c in full_list for c in ('"', '\\')):
        raise EmbedError("Unsafe initramfs list path")
    lines = spec.read_text(encoding="utf-8").splitlines()
    if len(lines) != 6 or tuple(lines[:5]) != STATIC_ENTRIES:
        raise EmbedError("Unexpected initramfs entries; only six fixed nodes are allowed")
    marker = "file /init "
    if not lines[5].startswith(marker) or not lines[5].endswith(" 0755 0 0"):
        raise EmbedError("Missing regular /init cpio entry")
    path = lines[5][len(marker):-len(" 0755 0 0")]
    binary = Path(path)
    if not binary.is_absolute() or binary.is_symlink() or not binary.is_file():
        raise EmbedError("/init binary must be an existing non-symlink absolute file")
    if binary.parent.resolve(strict=True) != spec.parent.resolve(strict=True):
        raise EmbedError("Init binary must reside beside generated initramfs list")
    if str(binary.resolve(strict=True)) != path:
        raise EmbedError("Noncanonical init binary path")
    if any(c.isspace() for c in path):
        raise EmbedError("Init binary path contains whitespace")
    elf = validate_init(binary)

    evidence_path = spec.parent / "initramfs-evidence.json"
    require_regular(evidence_path, "initramfs evidence")
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    if (evidence.get("status") != "NON_RELEASE_INITRAMFS_SPEC_ONLY"
            or evidence.get("init") != elf
            or evidence.get("complete_wearos_initramfs") is not False
            or evidence.get("image_flashed") is not False):
        raise EmbedError("Initramfs evidence differs from local ELF")
    # The config is a copy from the fork; require exactly the historically
    # expected value so future changes are not silently overridden.
    original = config.read_text(encoding="utf-8")
    if original.count(SOURCE_LINE) != 1:
        raise EmbedError("Kernel config has unexpected embedded initramfs source")
    replacement = f'CONFIG_INITRAMFS_SOURCE="{full_list}"'
    if replacement in original:
        raise EmbedError("Initramfs already configured")
    config.write_text(original.replace(SOURCE_LINE, replacement), encoding="utf-8")
    return {
        "schema": "galwear-r800-embedded-initramfs-smoke-v1",
        "status": "TEMPORARY_KCONFIG_SET_ONLY",
        "list_sha256": hashlib.sha256(spec.read_bytes()).hexdigest(),
        "init_sha256": elf["sha256"],
        "init_size": elf["size_bytes"],
        "entries": 6,
        "kernel_compiled": False,
        "boot_tested": False,
        "safe_to_flash": False,
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Validate generated /init and set temporary kernel Kconfig")
    p.add_argument("--config", required=True, type=Path)
    p.add_argument("--list", required=True, type=Path)
    p.add_argument("--report", required=True, type=Path)
    a = p.parse_args(argv)
    try:
        report = prepare_config(a.config, a.list)
        status = 0
    except (EmbedError, OSError, ValueError, KeyError, TypeError) as exc:
        report = {
            "schema": "galwear-r800-embedded-initramfs-smoke-v1",
            "status": "REJECT",
            "reason": str(exc),
            "kernel_compiled": False,
            "safe_to_flash": False,
        }
        status = 2
    a.report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n",
                        encoding="utf-8")
    print(report["status"])
    return status


if __name__ == "__main__":
    raise SystemExit(main())
