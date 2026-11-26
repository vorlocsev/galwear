#!/usr/bin/env python3
"""Offline Broadcom GPS export audit; never calls a donor function."""
import argparse
import hashlib
import json
from pathlib import Path
import struct

EXPORT = "gps_get_hardware_interface"


def assess(raw, info):
    problems = []
    flags = struct.unpack_from("<I", raw, 36)[0] if len(raw) >= 52 else 0
    if info["abi"] != "arm" or flags & 0xff000000 != 0x05000000 or flags & 0x400:
        problems.append("Expected ARM32 EABI5 without hard-float flag")
    if info["elf_type"] != "ET_DYN" or not info["has_dynamic"]:
        problems.append("Expected dynamic shared library")
    if info["dynamic_symbol_count"] is None or info["unsupported_symbols"]:
        problems.append("Incomplete symbol inventory")
    if info["custom_search_path"]:
        problems.append("Unexpected RPATH/RUNPATH")
    matches = [s for s in info["symbol_exports"] if s["name"] == EXPORT
               and not s["version_hidden"]]
    if len(matches) != 1 or matches[0]["type"] != 2 or matches[0]["weak"]:
        problems.append("Expected one strong default-visible function export")
    return {"status": "REVIEW_REQUIRED" if problems else "EXPORT_CANDIDATE",
            "problems": problems, "sha256": hashlib.sha256(raw).hexdigest(),
            "export": EXPORT, "candidate_count": len(matches),
            "dynamic_symbol_count": info["dynamic_symbol_count"],
            "needed": info["needed"], "hardware_interface_abi_verified": False,
            "xtra_abi_verified": False, "runtime_verified": False,
            "safe_to_flash": False}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--library", type=Path, required=True)
    args = p.parse_args()
    from r800_gps_link_gate import elf
    from r800_stage_gps_donors import read_source
    try:
        raw = read_source(args.library)
        report = assess(raw, elf(raw))
    except (OSError, ValueError, struct.error) as exc:
        report = {"status": "REVIEW_REQUIRED", "problems": [str(exc)],
                  "safe_to_flash": False}
    print(json.dumps(report, indent=2, sort_keys=True))
    return 2 if report["problems"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
