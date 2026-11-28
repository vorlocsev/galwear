#!/usr/bin/env python3
"""Compare independent PHH reference extractions; not a Wear OS donor proof."""
import argparse
import hashlib
import json
from pathlib import Path
import re

import r800_phh_runtime_reference as phh


def compare(first, second, source_sha):
    if not re.fullmatch(r"[0-9a-f]{40}", source_sha):
        raise ValueError("Expected full source SHA")
    errors = []
    expected = {
        "source_sha": source_sha, "status": "PHH_V313_ARM32_RUNTIME_STATIC_ONLY",
        "release_id": phh.RELEASE_ID, "asset_id": phh.ASSET_ID,
        "asset_name": phh.ASSET_NAME, "asset_bytes": phh.ASSET_SIZE,
        "source": phh.SOURCE, "asset_sha256_observed": phh.OBSERVED_ASSET_SHA256,
        "system_sha256": phh.OBSERVED_SYSTEM_SHA256, "system_bytes": phh.OBSERVED_SYSTEM_BYTES,
        "first_observation_pin_matched": True, "runtime_observation_pins_matched": True,
        "independent_asset_sha256_verified": False, "wear_os_donor": False,
        "runtime_executed": False, "safe_to_flash": False,
    }
    for label, report in (("first", first), ("second", second)):
        for key, value in expected.items():
            if type(report.get(key)) is not type(value) or report[key] != value:
                errors.append(label + ": invalid " + key)
        runtime = report.get("runtime", {})
        if not isinstance(runtime, dict):
            errors.append(label + ": malformed runtime")
            continue
        if (runtime.get("status") != "ARM32_BIONIC_RUNTIME_EXTRACTED_STATIC_ONLY" or
                runtime.get("system_sha256") != phh.OBSERVED_SYSTEM_SHA256):
            errors.append(label + ": invalid runtime status or source image")
        for flag in ("runtime_authenticity_verified", "android_version_verified",
                     "apex_signature_verified", "runtime_stub_exclusion_proven",
                     "runtime_verified", "safe_to_flash"):
            if runtime.get(flag) is not False:
                errors.append(label + ": invalid runtime hold " + flag)
        try:
            phh.verify_runtime_pins(runtime)
        except (KeyError, TypeError, AttributeError, ValueError):
            errors.append(label + ": invalid runtime pins")
    if first.get("runtime") != second.get("runtime"):
        errors.append("Runtime extraction reports differ")
    return {"schema": "galwear-r800-phh-extraction-comparison-v1",
            "status": "PHH_REFERENCE_EXTRACTION_REPORTS_MATCH" if not errors else "REVIEW_REQUIRED",
            "source_sha": source_sha, "errors": errors,
            "asset_sha256": phh.OBSERVED_ASSET_SHA256,
            "system_sha256": phh.OBSERVED_SYSTEM_SHA256,
            "reference_runtime_sha256": phh.OBSERVED_RUNTIME_SHA256,
            "wear_os_donor": False, "independent_asset_sha256_verified": False,
            "runtime_verified": False, "hardware_tested": False, "safe_to_flash": False}


def load(path):
    with path.open("rb") as stream:
        raw = stream.read(1024*1024+1)
    if len(raw) > 1024*1024:
        raise ValueError("Reference report exceeds size budget")
    result = json.loads(raw)
    if not isinstance(result, dict):
        raise ValueError("Expected reference JSON object")
    return result, hashlib.sha256(raw).hexdigest()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--first", type=Path, required=True)
    p.add_argument("--second", type=Path, required=True)
    p.add_argument("--source-sha", required=True)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    first, first_hash = load(a.first)
    second, second_hash = load(a.second)
    report = compare(first, second, a.source_sha)
    report["input_sha256"] = [first_hash, second_hash]
    with a.output.open("x", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2, sort_keys=True)
        stream.write("\n")
    print(report["status"])
    for error in report["errors"]:
        print("PHH_COMPARISON_ERROR:", error)
    return 2 if report["errors"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
