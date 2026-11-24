#!/usr/bin/env python3
"""Run repository unittest discovery and emit exact-head NON-RELEASE evidence."""
from __future__ import annotations
import argparse
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
    suite = unittest.defaultTestLoader.discover(str(repo / "tests"), pattern="test_*.py")
    expected_tests = suite.countTestCases()
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    report = {
        "schema": "galwear-r800-integrated-regression-v1",
        "commit": commit, "run_id": os.getenv("GITHUB_RUN_ID"),
        "run_attempt": os.getenv("GITHUB_RUN_ATTEMPT"),
        "discovered": expected_tests, "executed": result.testsRun,
        "failures": [t.id() for t, _ in result.failures],
        "errors": [t.id() for t, _ in result.errors],
        "skipped": [t.id() for t, _ in result.skipped],
        "expected_failures": [t.id() for t, _ in result.expectedFailures],
        "unexpected_successes": [t.id() for t in result.unexpectedSuccesses],
        "status": "PASS" if expected_tests > 0 and result.testsRun == expected_tests
                           and result.wasSuccessful() and not result.skipped
                           and not result.expectedFailures else "REVIEW_REQUIRED",
        "hardware_tested": False, "android_boot_tested": False,
        "safe_to_flash": False,
    }
    a.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
