#!/usr/bin/env python3
"""Read-only SM-R800 recovery-readiness evidence; NEVER flash/reboot a watch.

It checks a previously saved PIT, a local Wear OS archive, and an independent
Samsung combination reference. It cannot establish that a factory backup is
valid or that Wireless Download/USB recovery works on a particular watch.

PIT physical geometry/512-byte sectors are still assumptions, so even a
structural PASS ALWAYS means HOLD before hardware installation.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import struct
import sys

from r800_safety import (
    EXPECTED_IMAGES, PIT_HEADER_SIZE, PIT_ENTRY_SIZE,
    SafetyError, parse_pit_strict,
)
from r800_preflight_report import inspect_files, MAX_PIT_FILE_BYTES


PROTECTED_NAMES = frozenset((
    "CSA", "CM", "EFS", "PERSIST", "PERSISTENT",
    "CAL", "CALIB", "CALIBRATION", "NV", "NV_DATA", "CERT",
))
# No automatic flash retry/repartition is appropriate after an interrupted
# device write; exact on-watch state cannot be inferred from a socket error.
FAILURE_HANDLING = {
    "before_first_write": {
        "automatic_retry": False,
        "action": "Inspect offline inputs and protocol evidence; do not flash.",
    },
    "after_first_write_or_unknown": {
        "automatic_retry": False,
        "action": "Stop. Treat eMMC state as unknown. Obtain expert recovery evidence.",
    },
    "boot_failure": {
        "automatic_retry": False,
        "action": "Stop. Do not overwrite CM/CSA/EFS or assume wireless recovery.",
    },
}


def _decode(raw: bytes, description: str) -> str:
    try:
        return raw.split(b"\0", 1)[0].decode("ascii")
    except UnicodeDecodeError as exc:
        raise SafetyError(f"Non-ASCII PIT {description}") from exc


def _protected(part_name: str, file_name: str) -> bool:
    # Explicit full names, not substring search (CM must not match CMM).
    stem = file_name.lower().removesuffix(".bin").removesuffix(".img")
    return part_name.upper() in PROTECTED_NAMES or stem.upper() in PROTECTED_NAMES


def parse_all_pit_partitions(pit: bytes) -> list[dict]:
    """Inspect every PIT entry; don't ignore entries with empty flash filenames."""
    parse_pit_strict(pit)
    count = struct.unpack_from("<I", pit, 4)[0]
    entries = []
    for idx in range(count):
        entry = pit[PIT_HEADER_SIZE + idx * PIT_ENTRY_SIZE:
                    PIT_HEADER_SIZE + (idx + 1) * PIT_ENTRY_SIZE]
        device_type, ident = struct.unpack_from("<II", entry, 4)
        offset, blocks = struct.unpack_from("<II", entry, 20)
        name = _decode(entry[36:68], "partition name")
        flash = _decode(entry[68:100], "flash filename")
        if device_type > 3:
            raise SafetyError(f"Unknown PIT device type on entry {idx}")
        if blocks and offset + blocks > 0x100000000:
            raise SafetyError(f"PIT geometry overflow on entry {idx}")
        entries.append({
            "index": idx,
            "device_type": device_type,
            "identifier": ident,
            "offset": offset,
            "blocks": blocks,
            "partition_name": name,
            "flash_filename": flash,
            "protected": _protected(name, flash),
        })
    return entries


def validate_factory_boundaries(pit: bytes) -> dict:
    """Reject target-ID collisions or plausible target/protected overlaps.

    Same device_type and nonzero block intervals are treated as an assumed
    common address space. The sector interpretation is UNVERIFIED on hardware.
    """
    entries = parse_all_pit_partitions(pit)
    targets = {e["flash_filename"]: e for e in entries
               if e["flash_filename"] in EXPECTED_IMAGES}
    if set(targets) != set(EXPECTED_IMAGES):
        raise SafetyError("Missing target partition(s) in PIT")
    protected = [e for e in entries if e["protected"]]
    for item in protected:
        if item["flash_filename"] in EXPECTED_IMAGES:
            raise SafetyError(
                f"Protected partition targeted by firmware image {item['flash_filename']}")
        for target in targets.values():
            if item["identifier"] == target["identifier"]:
                raise SafetyError(
                    f"Protected/target PIT identifier conflict: {item['partition_name']}")
            if (item["device_type"] == target["device_type"] and
                    item["blocks"] and target["blocks"]):
                a0, a1 = item["offset"], item["offset"] + item["blocks"]
                b0, b1 = target["offset"], target["offset"] + target["blocks"]
                if max(a0, b0) < min(a1, b1):
                    raise SafetyError(
                        "Possible protected/target PIT overlap "
                        f"({item['partition_name']} / {target['flash_filename']})")
    # Never include factory data, device identifiers, or partition contents.
    found = sorted({e["partition_name"] or e["flash_filename"] for e in protected})
    return {
        "entries_inspected": len(entries),
        "targets_inspected": len(targets),
        "protected_entries_visible": len(protected),
        "protected_partition_labels": found,
        "factory_collision_detected": False,
        "geometry_interpretation_verified_on_device": False,
        "factory_data_read_or_modified": False,
    }


def recovery_readiness(
    package: str | Path, pit_file: str | Path, combination: str | Path,
) -> dict:
    """Produce evidence and blockers, NEVER a 'safe to flash' verdict."""
    if combination is None:
        raise SafetyError("Combination reference is required")
    package, pit_file, combination = map(Path, (package, pit_file, combination))
    if not 28 <= pit_file.stat().st_size <= MAX_PIT_FILE_BYTES:
        raise SafetyError("PIT size outside 28..65536 bytes")
    pit = pit_file.read_bytes()
    factory = validate_factory_boundaries(pit)
    evidence = inspect_files(package, pit_file, combination)
    blockers = [
        "No authenticated device-model, retail S-Boot or secure-boot evidence.",
        "No physical read-back or factory-partition backup verified.",
        "No independent proof that Wireless Download survives a partial flash.",
        "No tested wired/USB recovery path for this specific watch.",
        "PIT geometry and last Odin PIT block framing lack real-device traces.",
        "Combination archive SHA-256 match does not authenticate Samsung origin.",
    ]
    if not factory["protected_entries_visible"]:
        blockers.append("Factory CSA/CM/EFS entries not visible in supplied PIT.")
    return {
        "schema": "galwear-r800-recovery-readiness-v1",
        "decision": "HOLD_HARDWARE_UNVERIFIED",
        "safe_to_flash": False,
        "can_recover_after_flash_failure": False,
        "factory_backup_verified": False,
        "wired_recovery_verified": False,
        "wireless_recovery_verified": False,
        "retail_bootloader_compatibility_verified": False,
        "checks": {
            "offline_package_reference_pit": evidence["result"],
            "matching_reference_members": evidence.get(
                "reference_comparison", {}).get("matching_reference_members", 0),
            "factory_partition_bounds": factory,
        },
        "blockers": blockers,
        "failure_handling": FAILURE_HANDLING,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Offline SM-R800 recovery readiness only (never flashes/reboots)")
    parser.add_argument("--package", required=True)
    parser.add_argument("--pit-file", required=True)
    parser.add_argument("--combination", required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        report = recovery_readiness(args.package, args.pit_file, args.combination)
        rc = 0
    except (SafetyError, OSError, ValueError, KeyError) as exc:
        report = {
            "schema": "galwear-r800-recovery-readiness-v1",
            "decision": "REJECT_OFFLINE_EVIDENCE",
            "reason": str(exc),
            "safe_to_flash": False,
            "can_recover_after_flash_failure": False,
        }
        rc = 2
    args.report.write_text(
        json.dumps(report, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(f"[{'HOLD' if rc == 0 else 'REJECT'}] {report['decision']}; NEVER flash approval")
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
