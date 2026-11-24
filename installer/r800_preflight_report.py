#!/usr/bin/env python3
"""Offline SM-R800 flash-plan audit. No sockets, Odin commands or device I/O.

Do not treat a PASS result as authorization to flash. It proves only that
supplied local files satisfy the project's conservative structural checks.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from r800_safety import SafetyError, preflight_file
from r800_geometry import parse_pit_geometry, plan_image_transfers
from r800_recovery_audit import audit_release


MAX_PIT_FILE_BYTES = 64 * 1024


def inspect_files(
    package: str | Path,
    pit_file: str | Path,
    combination: str | Path | None = None,
) -> dict:
    """Inspect supplied local firmware and PIT, never contact a watch."""
    package = Path(package)
    pit_file = Path(pit_file)
    members = preflight_file(package)
    size = pit_file.stat().st_size
    if not 28 <= size <= MAX_PIT_FILE_BYTES:
        raise SafetyError(f"PIT file length out of bounds: {size}")
    pit = pit_file.read_bytes()
    geometry = parse_pit_geometry(pit)
    plan = plan_image_transfers(geometry, members)
    # The device could be R810 or another model with superficially similar PIT.
    report = {
        "result": "STRUCTURAL_PASS_ONLY",
        "package_filename": package.name,
        "pit_filename": pit_file.name,
        "partition_count_checked": len(geometry),
        "assumed_sector_bytes": 512,
        "transport_alignment_bytes": 131072,
        "images": plan,
        "source_authenticity_verified": False,
        "device_model_verified": False,
        "bootloader_signature_verified": False,
        "flashing_safe": False,
        "hardware_tested": False,
        "warnings": [
            "PIT file origin and watch model are not authenticated.",
            "Assumes 512-byte eMMC sectors for PIT block counts.",
            "Passing checks is not authorization to flash.",
        ],
    }
    if combination is not None:
        reference = audit_release(package, combination)
        report["reference_comparison"] = {
            "combination_filename": Path(combination).name,
            "matching_reference_members": len(reference["checks"]),
            "reference_matches": True,
            "source_authenticity_verified": False,
        }
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="SM-R800 offline firmware+PIT report; never flashes")
    parser.add_argument("--package", required=True, help="Local R800-WearOS.tar.md5")
    parser.add_argument("--pit-file", required=True, help="Previously saved PIT binary")
    parser.add_argument("--combination", help="Optional independently supplied reference firmware")
    parser.add_argument("--output", help="Optional JSON report path")
    args = parser.parse_args(argv)
    try:
        report = inspect_files(args.package, args.pit_file, args.combination)
        exit_code = 0
    except (SafetyError, OSError, ValueError) as exc:
        report = {
            "result": "REJECT",
            "reason": str(exc),
            "flashing_safe": False,
            "hardware_tested": False,
        }
        exit_code = 2
    output = json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True)
    if args.output:
        Path(args.output).write_text(output + "\n", encoding="utf-8")
    print(output, file=sys.stdout if exit_code == 0 else sys.stderr)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
