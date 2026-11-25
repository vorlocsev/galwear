#!/usr/bin/env python3
"""Run a required unittest suite; empty and incomplete runs fail closed."""
import argparse
from pathlib import Path
import unittest
import sys

def run_required(directory, pattern, runner=None):
    suite = unittest.defaultTestLoader.discover(str(directory), pattern=pattern)
    count = suite.countTestCases()
    if count == 0:
        print(f"Required test suite empty: {pattern}", file=sys.stderr)
        return 1
    result = (runner or unittest.TextTestRunner(verbosity=2)).run(suite)
    if (not result.wasSuccessful() or result.testsRun != count
            or result.skipped or result.expectedFailures):
        print(f"Required test suite incomplete or failed: {pattern}", file=sys.stderr)
        return 1
    return 0

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pattern")
    args = parser.parse_args()
    return run_required(Path(__file__).resolve().parents[1] / "tests", args.pattern)

if __name__ == "__main__":
    raise SystemExit(main())
