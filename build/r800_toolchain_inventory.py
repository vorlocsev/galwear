#!/usr/bin/env python3
"""Read-only compiler inventory for SM-R800 kernel reproducibility.

No toolchain installation, package downloads, kernel source mutations, builds,
or device interactions. A matching compiler report is only one build prerequisite.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import subprocess
import sys

KCONFIG = "src/kernel/r800.config"
TOOLS = {"clang": ("clang", "--version"),
         "lld": ("ld.lld", "--version"),
         "make": ("make", "--version"),
         "dtc": ("dtc", "--version")}
VERSION = re.compile(r"(?<![0-9])(\d+)\.(\d+)\.(\d+)(?![0-9])")


def from_config(content: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for key, output_name in (("CONFIG_CLANG_VERSION", "clang"),
                             ("CONFIG_LLD_VERSION", "lld")):
        matches = re.findall(rf"(?m)^{key}=(\d+)$", content)
        if len(matches) != 1:
            raise ValueError(f"Required unique kernel option missing: {key}")
        encoded = int(matches[0])
        ver = (encoded // 10000, (encoded // 100) % 100, encoded % 100)
        out[output_name] = ".".join(map(str, ver))
    return out


def parse_version(value: str) -> str | None:
    m = VERSION.search(value)
    return ".".join(m.groups()) if m else None


def inspect_toolchain(config_path: Path, commands: dict | None = None) -> dict:
    expected = from_config(config_path.read_text(encoding="utf-8"))
    selected = commands or TOOLS
    output = {}
    for name, argv in selected.items():
        try:
            run = subprocess.run(argv, capture_output=True, text=True,
                                 timeout=10, check=False)
        except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
            output[name] = {"available": False, "version": None}
            continue
        version = parse_version(run.stdout + "\n" + run.stderr)
        output[name] = {
            "available": run.returncode == 0,
            "version": version,
        }
    exact_match = all(output.get(name, {}).get("available") and
                      output[name].get("version") == version
                      for name, version in expected.items())
    return {
        "schema": "galwear-r800-toolchain-inventory-v1",
        "expected_from_kernel_config": expected,
        "observed": output,
        "clang_lld_versions_match_config": bool(exact_match),
        "kernel_built": False,
        "reproducible_build_proven": False,
        "safe_to_flash": False,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description="Read-only R800 toolchain inventory")
    parser.add_argument("--config", type=Path, default=Path(KCONFIG))
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--strict", action="store_true",
                        help="Fail if Clang/LLD versions differ from kernel config")
    args = parser.parse_args(argv)
    try:
        data = inspect_toolchain(args.config)
    except (ValueError, OSError) as exc:
        data = {"schema": "galwear-r800-toolchain-inventory-v1",
                "status": "REJECT", "reason": str(exc),
                "kernel_built": False, "safe_to_flash": False}
        status = 2
    else:
        status = 0 if data["clang_lld_versions_match_config"] or not args.strict else 2
        data["status"] = ("VERSIONS_MATCH" if data["clang_lld_versions_match_config"]
                          else "MISMATCH_OR_UNAVAILABLE")
    args.report.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n",
                           encoding="utf-8")
    print(data["status"], "- no kernel compilation attempted")
    return status


if __name__ == "__main__":
    raise SystemExit(main())
