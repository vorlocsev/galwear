#!/usr/bin/env python3
"""Static libbrcm GPS export evidence; never load or execute donor code."""
import argparse
import hashlib
import json
from pathlib import Path
import struct

from r800_android_linker_audit import inspect
from r800_android_userspace_preflight import read_regular

LIMIT = 64 * 1024**2
FACTORY = "gps_get_hardware_interface"
MARKER = b"gps-xtra\0"


def audit(raw):
    info = inspect(raw)
    if info["abi"] != "arm" or info["elf_type"] != "ET_DYN" or not info["has_dynamic"]:
        raise ValueError("Expected ARM32 dynamic shared library")
    flags = struct.unpack_from("<I", raw, 36)[0]
    if flags & 0xff000000 != 0x05000000 or flags & 0x400:
        raise ValueError("Expected ARM EABI5 without hard-float flag")
    exports = info["symbol_exports"]
    factory = [s for s in exports if s["name"] == FACTORY]
    callable_candidates = [s for s in factory if s["type"] == 2
                           and s["binding"] in (1, 2)
                           and s["visibility"] in (0, 3)
                           and not s["version_hidden"]]
    clues = [s for s in exports if any(key in s["name"].lower()
                                      for key in ("xtra", "lto", "get_extension"))]
    problems = []
    if info["dynamic_symbol_count"] is None or info["unsupported_symbols"]:
        problems.append("Incomplete supported dynamic symbol inventory")
    if info["soname"] not in (None, "libbrcm.so"):
        problems.append("Unexpected SONAME")
    if len(callable_candidates) != 1:
        problems.append("Expected one visible default-version STT_FUNC factory candidate")
    return {"schema": "galwear-r800-gps-export-evidence-v1",
            "status": "STATIC_EXPORT_EVIDENCE_ONLY" if not problems else "REVIEW_REQUIRED",
            "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw),
            "arm_flags": flags, "soname": info["soname"], "needed": info["needed"],
            "factory_exports": factory, "factory_candidates": callable_candidates,
            "xtra_export_clues": clues[:256], "xtra_export_clue_count": len(clues),
            "xtra_literal_count": raw.count(MARKER),
            "xtra_literal_first_offset": raw.find(MARKER) if MARKER in raw else None,
            "problems": problems, "factory_signature_verified": False,
            "extension_available_verified": False, "callback_layout_verified": False,
            "selected_abi": None, "runtime_verified": False, "safe_to_flash": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--library", type=Path, required=True,
                        help="Resolved local regular file from the donor firmware")
    args = parser.parse_args()
    try:
        report = audit(read_regular(args.library, LIMIT))
    except (OSError, ValueError, struct.error) as exc:
        report = {"status": "REVIEW_REQUIRED", "problems": [str(exc)],
                  "selected_abi": None, "runtime_verified": False, "safe_to_flash": False}
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["status"] == "STATIC_EXPORT_EVIDENCE_ONLY" else 2


if __name__ == "__main__":
    raise SystemExit(main())
