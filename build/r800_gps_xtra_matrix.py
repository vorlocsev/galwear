#!/usr/bin/env python3
"""Run all three XTRA ABI repeatability checks; never select a runtime ABI."""
import argparse
import json
from pathlib import Path
import subprocess

from r800_gps_repeatability import compare

MODES = {0: "disabled", 1: "legacy_candidate", 2: "sized_candidate"}


def matrix(builder, ndk, donor, timeout=300):
    rows = []
    for abi, name in MODES.items():
        try:
            result = compare(builder, ndk, donor, abi, timeout=timeout)
            if (result["schema"] != "galwear-r800-gps-repeatability-v1"
                    or type(result["xtra_abi"]) is not int
                    or result["xtra_abi"] != abi
                    or result["safe_to_flash"] is not False
                    or result["runtime_verified"] is not False
                    or result["independent_hosts_tested"] is not False
                    or result["status"] not in ("LOCAL_REPEATABILITY_PASS",
                                                "LOCAL_REPEATABILITY_FAIL")):
                raise ValueError("Invalid repeatability result scope")
            runs = result["runs"]
            if len(runs) != 2:
                raise ValueError("Expected two build records")
            expected = "-DR800_XTRA_ABI=" + str(abi)
            for run in runs:
                flags = [arg for arg in run["compiler_argv"]
                         if arg.startswith("-DR800_XTRA_ABI")]
                if flags != [expected]:
                    raise ValueError("Compiler evidence does not match requested ABI")
            if result["status"] == "LOCAL_REPEATABILITY_PASS":
                if result["differences"] or runs[0] != runs[1]:
                    raise ValueError("Inconsistent repeatability PASS")
        except (OSError, ValueError, KeyError, IndexError, TypeError,
                subprocess.TimeoutExpired) as exc:
            result = {"status": "LOCAL_REPEATABILITY_FAIL", "error": str(exc)}
        rows.append({"abi": abi, "mode": name, "repeatability": result,
                     "runtime_compatibility": "NOT_TESTED"})
    passed = [row for row in rows
              if row["repeatability"]["status"] == "LOCAL_REPEATABILITY_PASS"]
    cross_mode_differences = []
    if len(passed) > 1:
        reference = passed[0]["repeatability"]["runs"][0]
        for row in passed[1:]:
            run = row["repeatability"]["runs"][0]
            for key in ("donor_sha256", "input_fingerprints"):
                if run[key] != reference[key]:
                    cross_mode_differences.append({"abi": row["abi"], "field": key})
    ok = len(passed) == len(MODES) and not cross_mode_differences
    return {"schema": "galwear-r800-gps-xtra-matrix-v1",
            "status": "LOCAL_MATRIX_PASS" if ok else "LOCAL_MATRIX_FAIL",
            "modes": rows, "passed_modes": len(passed),
            "cross_mode_differences": cross_mode_differences,
            "selected_abi": None, "runtime_verified": False,
            "safe_to_flash": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ndk", type=Path, required=True)
    parser.add_argument("--donor", type=Path, required=True)
    parser.add_argument("--timeout", type=int, default=300)
    args = parser.parse_args()
    if not 1 <= args.timeout <= 1800:
        parser.error("timeout must be 1..1800 seconds per build")
    builder = Path(__file__).resolve().parents[1] / "src/tools/gps/build.sh"
    try:
        report = matrix(builder, args.ndk.resolve(strict=True),
                        args.donor.resolve(strict=True), args.timeout)
    except OSError as exc:
        report = {"status": "LOCAL_MATRIX_FAIL", "error": str(exc),
                  "safe_to_flash": False}
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["status"] == "LOCAL_MATRIX_PASS" else 2


if __name__ == "__main__":
    raise SystemExit(main())
