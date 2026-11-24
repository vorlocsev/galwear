#!/usr/bin/env python3
"""Run repository unittest discovery and emit exact-head NON-RELEASE evidence."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import unittest


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--repo", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    repo = a.repo.resolve()
    commit = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"],
                                     text=True).strip()
    expected = os.environ.get("GITHUB_SHA")
    if expected and expected != commit:
        p.error("Checkout SHA does not match triggering SHA")
    patch = repo / "src/kernel/r800-wearos.patch"
    patch_sha256 = hashlib.sha256(patch.read_bytes()).hexdigest()
    required_modules = {
        "test_pmucal_suspend_guard", "test_pd_rollback", "test_pmucal_status",
        "test_pmucal_rae_status", "test_pmucal_rae_snapshot",
        "test_wakeup_mask_transaction", "test_acpm_mif_checked",
        "test_flexpmu_lifecycle",
    }
    def flatten(suite):
        for item in suite:
            if isinstance(item, unittest.TestSuite):
                yield from flatten(item)
            else:
                yield item.id()
    suite = unittest.defaultTestLoader.discover(str(repo / "tests"), pattern="test_*.py")
    expected_tests = suite.countTestCases()
    discovered_ids = list(flatten(suite))
    discovered_modules = {test.split('.')[0] for test in discovered_ids}
    missing_modules = sorted(required_modules - discovered_modules)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    report = {
        "schema": "galwear-r800-integrated-regression-v1",
        "commit": commit, "run_id": os.getenv("GITHUB_RUN_ID"),
        "run_attempt": os.getenv("GITHUB_RUN_ATTEMPT"),
        "patch_sha256": patch_sha256,
        "required_power_modules": sorted(required_modules),
        "missing_power_modules": missing_modules,
        "discovered": expected_tests, "executed": result.testsRun,
        "failures": [t.id() for t, _ in result.failures],
        "errors": [t.id() for t, _ in result.errors],
        "skipped": [t.id() for t, _ in result.skipped],
        "expected_failures": [t.id() for t, _ in result.expectedFailures],
        "unexpected_successes": [t.id() for t in result.unexpectedSuccesses],
        "status": "PASS" if expected_tests > 0 and result.testsRun == expected_tests
                           and result.wasSuccessful() and not result.skipped
                           and not result.expectedFailures and not missing_modules else "REVIEW_REQUIRED",
        "hardware_tested": False, "android_boot_tested": False,
        "safe_to_flash": False,
    }
    a.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
