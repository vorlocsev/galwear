#!/usr/bin/env python3
"""Validate exact-head integrated NON-RELEASE CI evidence; no binary execution."""
import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path

BASE = "50db73fc799f20a7120a8b5f653b16cc123d856f"
MODULES = {"audio_r800": "audio.primary.r800.so", "gps_r800": "gps.r800.so",
           "sensors_r800": "sensors.r800.so", "hwcomposer_r800": "hwcomposer.r800.so"}
HEX = re.compile(r"[0-9a-f]{64}")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read(path):
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= 1024 * 1024,
            "Missing or oversized report: " + path.name)
    obj = json.loads(path.read_text(encoding="utf-8"))
    require(isinstance(obj, dict), "Report must be an object")
    return obj


def validate(repo, directory, commit, run_id, attempt):
    specs = {
        "r800-integrated-regression.json": ("galwear-r800-integrated-regression-v1", "PASS"),
        "hal-compile.json": ("galwear-r800-hal-compile-v1", "FOUR_ARM32_OBJECTS_COMPILED"),
        "hal-link.json": ("galwear-r800-hal-link-v1", "FOUR_ARM32_HAL_LIBRARIES_LINKED"),
        "decon-abi.json": ("galwear-r800-decon-abi-v1", "LAYOUT_COMPILED_BOTH_ABIS"),
    }
    reports = {}
    for name, (schema, status) in specs.items():
        obj = read(directory / name)
        require(obj.get("schema") == schema and obj.get("status") == status, "Rejected status: " + name)
        require(obj.get("commit") == commit and obj.get("run_id") == run_id and
                obj.get("run_attempt") == attempt, "Stale run identity: " + name)
        require(obj.get("safe_to_flash") is False, "Invalid safety flag: " + name)
        reports[name] = obj
    tests = reports["r800-integrated-regression.json"]
    require(type(tests.get("executed")) is int and tests["executed"] > 0 and
            tests["executed"] == tests.get("discovered"), "Incomplete regression execution")
    for key in ("failures", "errors", "skipped", "expected_failures", "unexpected_successes"):
        require(tests.get(key) == [], "Nonempty or missing test field: " + key)
    comp = reports["hal-compile.json"]
    link = reports["hal-link.json"]
    abi = reports["decon-abi.json"]
    require(comp.get("abi") == "armeabi-v7a" and comp.get("api_level") == 28 and
            comp.get("ndk") == "27.2.12479018", "Unexpected Android toolchain")
    require(set(comp.get("objects", {})) == set(MODULES), "Incomplete object set")
    require(set(link.get("modules", {})) == set(MODULES.values()), "Incomplete linked set")
    for stem, name in MODULES.items():
        obj = comp["objects"][stem]
        so = link["modules"][name]
        require(obj.get("source_sha256") == digest(repo / "src/hal" / (stem + ".c")),
                "Source mismatch: " + stem)
        require(HEX.fullmatch(str(obj.get("object_sha256", ""))) and
                HEX.fullmatch(str(so.get("sha256", ""))) and so.get("hmi_exported") is True and
                so.get("soname") == name, "Invalid binary metadata: " + name)
    require(link.get("compile_evidence_sha256") == digest(directory / "hal-compile.json"),
            "Compile/link evidence mismatch")
    require(link.get("tinyalsa_patch_sha256") == digest(repo / "build/patches/tinyalsa-2.0.0-sync-ptr.patch"),
            "tinyalsa patch mismatch")
    require(abi.get("source_commit") == BASE and abi.get("targets") == ["armv7a", "aarch64"] and
            abi.get("mirror_sha256") == digest(repo / "src/hal/r800_decon_abi.h"),
            "DECON ABI evidence mismatch")
    patch = read(directory / "r800-patch-check.json")
    require(patch.get("schema") == "galwear-r800-kernel-preflight-v1" and
            patch.get("status") == "PATCH_APPLIES_TO_PINNED_SOURCE_ONLY" and
            patch.get("safe_to_flash") is False and patch.get("patch_matches_supplied_kernel_tree") is True and
            patch.get("source_audit", {}).get("pinned_source_base_sha") == BASE and
            patch.get("source_audit", {}).get("git_apply_check") == "PASS" and
            patch.get("static_patch_audit", {}).get("patch_sha256") == digest(repo / "src/kernel/r800-wearos.patch") and
            patch.get("kernel_config_audit", {}).get("config_sha256") == digest(repo / "src/kernel/r800.config") and
            patch.get("device_tree_sha256") == digest(repo / "src/dt/r800.dts"), "Pinned patch evidence mismatch")
    return {"schema": "galwear-r800-integration-evidence-v1",
            "status": "HOST_REGRESSION_AND_HAL_LINK_EVIDENCE_MATCH",
            "commit": commit, "run_id": run_id, "run_attempt": attempt,
            "tests_executed": tests["executed"], "hal_modules": sorted(MODULES.values()),
            "evidence_sha256": {name: digest(directory / name) for name in
                                (*specs, "r800-patch-check.json")},
            "kernel_compiled": False, "android_boot_tested": False,
            "hardware_tested": False, "safe_to_flash": False}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--repo", type=Path, required=True)
    p.add_argument("--directory", type=Path, required=True)
    p.add_argument("--commit", required=True)
    p.add_argument("--run-id", required=True)
    p.add_argument("--attempt", required=True)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    require(subprocess.check_output(["git", "-C", str(a.repo), "rev-parse", "HEAD"], text=True).strip()
            == a.commit, "Wrong checkout")
    try:
        report = validate(a.repo, a.directory, a.commit, a.run_id, a.attempt)
        code = 0
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
        report = {"schema": "galwear-r800-integration-evidence-v1", "status": "REJECT",
                  "commit": a.commit, "run_id": a.run_id, "run_attempt": a.attempt,
                  "reason": str(exc), "safe_to_flash": False}
        code = 1
    a.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(report["status"])
    return code


if __name__ == "__main__":
    raise SystemExit(main())
