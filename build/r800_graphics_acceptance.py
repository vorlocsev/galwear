#!/usr/bin/env python3
"""Combine same-head offline graphics evidence, never promote release readiness."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re

from r800_graphics_fixture_summary import HWC_FLAGS, EGL_FLAGS
from r800_android_graphics_abi import LIBHARDWARE, SYSTEM_CORE, expressions

HOLDS = ("hardware_tested", "safe_to_flash")
FIXTURE_HOLDS = ("donor_surfaceflinger_verified", "donor_mapper_verified",
                 "donor_mali_verified", "real_sync_file_verified",
                 "android_boot_tested") + HOLDS
ABI_HOLDS = ("donor_layer_stride_100_verified", "mapper_2_1_verified",
             "donor_runtime_verified") + HOLDS


DONOR_CHECKS = (
    "graphics_dependency_candidates", "surfaceflinger_abi_known",
    "surfaceflinger_graph_root", "egl_candidates", "graphics_exports",
    "mapper_2_1_candidates", "mapper_factory_export", "mali_recipe_candidates",
    "hwc_explicit_stride_hint", "vintf_literal_inventory",
)
BINDING_HOLDS = ("original_image_authenticity_verified",
                 "extraction_provenance_verified", "runtime_verified", "safe_to_flash")


def valid_digest(value):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def valid_tree(value):
    return (isinstance(value, dict) and set(value) == {
        "algorithm", "sha256", "entries", "regular_bytes"} and
        value["algorithm"] == "sha256-ordered-tree-records-v1" and
        valid_digest(value["sha256"]) and
        type(value["entries"]) is int and 0 < value["entries"] <= 250000 and
        type(value["regular_bytes"]) is int and 0 < value["regular_bytes"] <= 32*1024**3)


def check_donor_binding(donor, source_sha, preflight):
    """Check reported reproducibility fields, not independent authenticity."""
    binding = donor.get("donor_binding")
    errors = []
    if not isinstance(binding, dict):
        return ["Missing or malformed donor binding"]
    if (binding.get("schema") != "galwear-r800-extracted-donor-binding-v1" or
            binding.get("source_sha") != source_sha or donor.get("source_sha") != source_sha):
        errors.append("Donor binding schema or source SHA mismatch")
    before, after = binding.get("tree_before"), binding.get("tree_after")
    if not valid_tree(before) or not valid_tree(after) or before != after:
        errors.append("Donor tree fingerprint invalid or changed")
    for key in ("tracked_checkout_clean", "tree_unchanged_observed"):
        if binding.get(key) is not True:
            errors.append("Missing donor binding flag: " + key)
    for key in BINDING_HOLDS:
        if binding.get(key) is not False:
            errors.append("Invalid donor binding hold: " + key)
    for key in ("config_sha256", "dtb_sha256"):
        if key not in binding or (binding[key] is not None and not valid_digest(binding[key])):
            errors.append("Invalid kernel input digest: " + key)
    checks = preflight.get("checks")
    if not isinstance(checks, dict) or set(checks) != set(DONOR_CHECKS) or any(
            type(value) is not bool for value in checks.values()):
        errors.append("Incomplete donor prerequisite check set")
    else:
        missing = [key for key in DONOR_CHECKS if not checks[key]]
        if preflight.get("missing_static_prerequisites") != missing:
            errors.append("Inconsistent donor prerequisite failures")
        expected = "REVIEW_REQUIRED" if missing else "STATIC_DONOR_PREREQUISITES_ONLY"
        if preflight.get("status") != expected:
            errors.append("Inconsistent donor prerequisite status")
        if not missing and (not valid_digest(binding.get("config_sha256")) or
                            not valid_digest(binding.get("dtb_sha256"))):
            errors.append("Complete donor prerequisites require config and DTB digests")
        if checks["graphics_dependency_candidates"] != (
                donor.get("status") == "STATIC_GRAPHICS_DEPENDENCY_CANDIDATES_ONLY"):
            errors.append("Inconsistent donor ELF graph status")
    if preflight.get("release_status") != "HOLD_HARDWARE_UNVERIFIED":
        errors.append("Invalid donor preflight release hold")
    return errors


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
    expected_fields = set(expressions())
    if type(count) is not int or count != len(expected_fields):
        errors.append("ABI field count incomplete")
    for arch, pointer_size in (("arm", 4), ("arm64", 8)):
        layout = layouts.get(arch, {})
        aosp, local = layout.get("aosp"), layout.get("local")
        if (not isinstance(aosp, dict) or not isinstance(local, dict) or
                aosp != local or set(aosp) != expected_fields or
                aosp.get("pointer_bytes") != pointer_size or layout.get("differences") != {}):
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
        # Legacy reports remain unbound; bound reports are checked below.
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
        if "donor_binding" in donor:
            binding_errors = check_donor_binding(donor, source_sha, preflight)
            if binding_errors:
                errors.extend(binding_errors)
                donor_summary["status"] = "INVALID_BOUND_REPORT_REVIEW_REQUIRED"
            else:
                complete = preflight["status"] == "STATIC_DONOR_PREREQUISITES_ONLY"
                donor_summary.update(
                    status="BOUND_STATIC_PREREQUISITES_ONLY" if complete else "BOUND_STATIC_REPORT_REVIEW_REQUIRED",
                    source_sha_bound=True,
                    reported_tree_fingerprint=donor["donor_binding"]["tree_before"]["sha256"],
                    reported_tree_unchanged=True,
                    static_prerequisites_complete=complete,
                )
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
    for error in result["errors"]:
        print("GRAPHICS_ACCEPTANCE_ERROR:", error)
    return 2 if result["errors"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
