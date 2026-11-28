#!/usr/bin/env python3
"""Combine same-head offline graphics evidence, never promote release readiness."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re

from r800_graphics_fixture_summary import HWC_FLAGS, EGL_FLAGS
from r800_android_graphics_abi import LIBHARDWARE, SYSTEM_CORE

HOLDS = ("hardware_tested", "safe_to_flash")
FIXTURE_HOLDS = ("donor_surfaceflinger_verified", "donor_mapper_verified",
                 "donor_mali_verified", "real_sync_file_verified",
                 "android_boot_tested") + HOLDS
ABI_HOLDS = ("donor_layer_stride_100_verified", "mapper_2_1_verified",
             "donor_runtime_verified") + HOLDS


def combine(abi, fixture, source_sha, donor=None):
    if not re.fullmatch(r"[0-9a-f]{40}", source_sha):
        raise ValueError("Expected full source SHA")
    errors = []
    for label, report, status, holds in (
        ("abi", abi, "AOSP11_LEGACY_GRAPHICS_LAYOUT_ONLY", ABI_HOLDS),
        ("fixture", fixture, "SYNTHETIC_GRAPHICS_PIPELINE_ONLY", FIXTURE_HOLDS),
    ):
        if report.get("source_sha") != source_sha:
            errors.append(label + ": source SHA mismatch")
        if report.get("status") != status:
            errors.append(label + ": unexpected status")
        for key in holds:
            if report.get(key) is not False:
                errors.append(label + ": invalid hold " + key)
    if (abi.get("aosp_libhardware_commit") != LIBHARDWARE or
            abi.get("aosp_system_core_commit") != SYSTEM_CORE):
        errors.append("ABI reference pins mismatch")
    count = abi.get("fields_per_abi")
    layouts = abi.get("layouts", {})
    if type(count) is not int or count < 97:
        errors.append("ABI field count incomplete")
    for arch in ("arm", "arm64"):
        layout = layouts.get(arch, {})
        aosp, local = layout.get("aosp"), layout.get("local")
        if (not isinstance(aosp, dict) or not isinstance(local, dict) or
                aosp != local or len(aosp) != count or layout.get("differences") != []):
            errors.append("ABI layout mismatch: " + arch)
    if layouts.get("arm", {}).get("aosp", {}).get("hwc_layer_1_t.size") != 96:
        errors.append("ARM32 HWC layer size mismatch")
    if fixture.get("schema") != "galwear-r800-graphics-fixture-summary-v1":
        errors.append("Unexpected fixture schema")
    if fixture.get("errors") != [] or fixture.get("release_status") != "HOLD_HARDWARE_UNVERIFIED":
        errors.append("Invalid fixture result or release hold")
    for section, keys in (("hwc_flags", HWC_FLAGS), ("egl_flags", EGL_FLAGS)):
        flags = fixture.get(section, {})
        for key in keys:
            if flags.get(key) is not True:
                errors.append("Missing fixture flag: " + key)
    donor_summary = {"status": "NOT_PROVIDED", "source_sha_bound": False,
                     "input_provenance_verified": False,
                     "static_prerequisites_complete": False}
    if donor is not None:
        preflight = donor.get("donor_preflight", {})
        # The legacy donor ELF report is not source-SHA bound. Preserve its
        # observations but never merge them as exact-head acceptance evidence.
        donor_summary.update(
            status="UNBOUND_STATIC_REPORT_REVIEW_REQUIRED",
            reported_status=preflight.get("status"),
            missing_static_prerequisites=preflight.get("missing_static_prerequisites"),
            reported_checks=preflight.get("checks"),
            runtime_blockers=preflight.get("runtime_blockers"),
        )
        if donor.get("safe_to_flash") is not False or any(
                preflight.get(key) is not False for key in (
                    "donor_surfaceflinger_verified", "donor_mapper_verified",
                    "donor_mali_verified", "hardware_tested", "safe_to_flash")):
            errors.append("Invalid donor report holds")
    return {
        "schema": "galwear-r800-graphics-acceptance-v1",
        "source_sha": source_sha,
        "status": "OFFLINE_GRAPHICS_EVIDENCE_ONLY" if not errors else "REVIEW_REQUIRED",
        "errors": errors, "same_head_abi_fixture_passed": not errors,
        "donor": donor_summary,
        "donor_surfaceflinger_verified": False, "donor_mapper_verified": False,
        "donor_mali_verified": False, "real_sync_file_verified": False,
        "android_boot_tested": False, "hardware_tested": False,
        "release_status": "HOLD_HARDWARE_UNVERIFIED", "safe_to_flash": False,
    }


def read_report(path, limit=2*1024*1024):
    with path.open("rb") as stream:
        raw = stream.read(limit+1)
    if len(raw) > limit:
        raise ValueError("Evidence exceeds size budget")
    data = json.loads(raw)
    if not isinstance(data, dict):
        raise ValueError("Expected JSON object")
    return data, hashlib.sha256(raw).hexdigest()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--abi", type=Path, required=True)
    p.add_argument("--fixture", type=Path, required=True)
    p.add_argument("--donor", type=Path)
    p.add_argument("--source-sha", required=True)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    abi, abi_hash = read_report(a.abi)
    fixture, fixture_hash = read_report(a.fixture)
    donor, donor_hash = read_report(a.donor, 96*1024*1024) if a.donor else (None, None)
    result = combine(abi, fixture, a.source_sha, donor)
    result["input_sha256"] = {"abi": abi_hash, "fixture": fixture_hash, "donor": donor_hash}
    with a.output.open("x", encoding="utf-8") as stream:
        json.dump(result, stream, sort_keys=True, indent=2)
        stream.write("\n")
    print(result["status"])
    return 2 if result["errors"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
