#!/usr/bin/env python3
"""Audit linked HAL ELF metadata; never load or execute the shared objects."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

NAMES = ("audio.primary.r800.so", "gps.r800.so", "sensors.r800.so", "hwcomposer.r800.so")
ALLOWED = {"libc.so", "libdl.so", "libm.so", "liblog.so"}


def inspect(header, symbols, dynamic, name):
    if not re.search(r"Class:\s+ELF32\b", header) or not re.search(r"Machine:\s+ARM\b", header):
        raise ValueError("Wrong ELF class or machine: " + name)
    if not re.search(r"Type:\s+DYN\b", header):
        raise ValueError("Not a shared object: " + name)
    hmi = [line for line in symbols.splitlines()
           if re.search(r"\bOBJECT\s+GLOBAL\s+DEFAULT\s+\d+\s+HMI\s*$", line)]
    if len(hmi) != 1:
        raise ValueError("Missing/ambiguous exported HMI: " + name)
    soname = re.findall(r"\(SONAME\).*?\[([^\]]+)\]", dynamic)
    if soname != [name]:
        raise ValueError("Incorrect SONAME: " + name)
    needed = sorted(re.findall(r"\(NEEDED\).*?\[([^\]]+)\]", dynamic))
    if set(needed) - ALLOWED:
        raise ValueError("Unexpected dynamic dependency: " + name)
    if re.search(r"\((?:RPATH|RUNPATH|TEXTREL)\)", dynamic):
        raise ValueError("Unexpected loader path or text relocation: " + name)
    return {"needed": needed, "soname": name, "hmi_exported": True}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--directory", type=Path, required=True)
    p.add_argument("--compile-report", type=Path, required=True)
    p.add_argument("--patch", type=Path, required=True)
    p.add_argument("--readelf", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    base = json.loads(a.compile_report.read_text())
    if base.get("status") != "FOUR_ARM32_OBJECTS_COMPILED" or base.get("safe_to_flash") is not False:
        raise ValueError("Invalid compile evidence")
    if os.getenv("GITHUB_SHA") and base["commit"] != os.environ["GITHUB_SHA"]:
        raise ValueError("Compile evidence commit mismatch")
    report = {}
    for name in NAMES:
        path = a.directory / name
        if not path.is_file() or path.is_symlink():
            raise ValueError("Missing regular HAL: " + name)
        def read(flag):
            return subprocess.check_output([str(a.readelf), flag, str(path)], text=True, timeout=15)
        report[name] = inspect(read("-h"), read("--dyn-syms"), read("-d"), name)
        report[name]["sha256"] = sha(path)
    result = {"schema": "galwear-r800-hal-link-v1", "status": "FOUR_ARM32_HAL_LIBRARIES_LINKED",
              "commit": base["commit"], "run_id": base["run_id"], "run_attempt": base["run_attempt"],
              "compile_evidence_sha256": sha(a.compile_report), "tinyalsa_patch_sha256": sha(a.patch),
              "modules": report, "abi_runtime_verified": False, "android_boot_tested": False,
              "hardware_tested": False, "safe_to_flash": False}
    a.output.write_text(json.dumps(result, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
