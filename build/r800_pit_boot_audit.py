#!/usr/bin/env python3
"""Read-only R800 PIT/boot capacity audit. Never authorizes flashing."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "installer"))
from r800_safety import EXPECTED_IMAGES, SafetyError
from r800_geometry import parse_pit_geometry, SECTOR_BYTES
from r800_recovery_readiness import parse_all_pit_partitions, validate_factory_boundaries

SCHEMA = "galwear-r800-pit-boot-audit-v1"
HISTORICAL_BOOT_BYTES = 18874368
MAX_PIT_BYTES = 65536


def inspect(pit: bytes, candidate_bytes: int | None = None) -> dict:
    if not 28 <= len(pit) <= MAX_PIT_BYTES:
        raise SafetyError("PIT size outside audit bounds")
    geometry = parse_pit_geometry(pit)
    entries = parse_all_pit_partitions(pit)
    factory = validate_factory_boundaries(pit)
    targets = [e for e in entries if e["flash_filename"] in EXPECTED_IMAGES]
    issues = []
    for target in targets:
        if not target["partition_name"]:
            issues.append("EMPTY_TARGET_PARTITION_NAME:" + target["flash_filename"])
        for other in entries:
            if target["index"] == other["index"]:
                continue
            if target["identifier"] == other["identifier"]:
                issues.append("TARGET_ID_COLLISION:" + target["flash_filename"]
                              + ":" + str(other["index"]))
            if target["device_type"] != other["device_type"]:
                continue
            if not other["blocks"]:
                issues.append("UNKNOWN_NEIGHBOR_GEOMETRY:" + str(other["index"]))
                continue
            a0, a1 = target["offset"], target["offset"] + target["blocks"]
            b0, b1 = other["offset"], other["offset"] + other["blocks"]
            if max(a0, b0) < min(a1, b1):
                lo, hi = sorted((target["index"], other["index"]))
                issues.append(f"POSSIBLE_TARGET_RANGE_OVERLAP:{lo}:{hi}")
    boot = geometry["dzImage"]
    recovery = geometry["dzImage-recovery"]
    if boot.capacity_bytes != HISTORICAL_BOOT_BYTES:
        issues.append("BOOT_CAPACITY_DIFFERS_FROM_HISTORICAL_18_MIB")
    if candidate_bytes is not None:
        if not 0 < candidate_bytes <= 4 * 1024**3:
            raise SafetyError("Candidate size outside audit bounds")
        if candidate_bytes > boot.capacity_bytes:
            issues.append("CANDIDATE_EXCEEDS_ASSUMED_BOOT_CAPACITY")
    blockers = [
        "PIT_ORIGIN_AND_DEVICE_IDENTITY_UNVERIFIED",
        "SECTOR_SIZE_AND_PHYSICAL_BANK_MAPPING_UNVERIFIED",
        "RETAIL_SBOOT_SIGNATURE_POLICY_UNVERIFIED",
        "RECOVERY_PATH_UNVERIFIED",
    ]
    if not factory["protected_entries_visible"]:
        blockers.append("FACTORY_PARTITIONS_NOT_VISIBLE")
    return {
        "schema": SCHEMA,
        "status": "STATIC_LAYOUT_CONFLICT" if issues else "STATIC_LAYOUT_ONLY",
        "pit_sha256": hashlib.sha256(pit).hexdigest(),
        "entries": len(entries),
        "assumed_sector_bytes": SECTOR_BYTES,
        "boot": {"id": boot.identifier, "offset_blocks": boot.offset_blocks,
                 "assumed_capacity_bytes": boot.capacity_bytes},
        "recovery": {"id": recovery.identifier, "offset_blocks": recovery.offset_blocks,
                     "assumed_capacity_bytes": recovery.capacity_bytes},
        "candidate_bytes": candidate_bytes,
        "historical_boot_bytes": HISTORICAL_BOOT_BYTES,
        "factory": factory,
        "layout_issues": sorted(set(issues)),
        "boot_blockers": blockers,
        "safe_to_flash": False,
        "device_contacted": False,
        "retail_sboot_verified": False,
    }


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--pit", type=Path, required=True)
    p.add_argument("--candidate-bytes", type=int)
    p.add_argument("--report", type=Path, required=True)
    a = p.parse_args()
    try:
        if a.pit.is_symlink() or not a.pit.is_file():
            raise SafetyError("PIT must be a regular non-symlink file")
        with a.pit.open("rb") as stream:
            raw = stream.read(MAX_PIT_BYTES + 1)
        result = inspect(raw, a.candidate_bytes)
        rc = 2 if result["layout_issues"] else 0
    except (OSError, ValueError, KeyError) as exc:
        result = {"schema": SCHEMA, "status": "REJECT", "reason": str(exc),
                  "safe_to_flash": False, "device_contacted": False}
        rc = 2
    a.report.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(result["status"])
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
