#!/usr/bin/env python3
"""Compile explicit hash-pinned CIL inputs with neverallow enabled, no policy load."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

from r800_android_userspace_preflight import read_regular
from r800_android_sepolicy_audit import header

MAX_INPUT = 4 * 1024**2
MAX_TOTAL = 32 * 1024**2
MAX_POLICY = 16 * 1024**2


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def compile_cil(inputs, tool):
    if not 1 <= len(inputs) <= 32:
        raise ValueError("Expected 1..32 explicit CIL files")
    tool = Path(tool).resolve(strict=True)
    tool_sha = sha(read_regular(tool, MAX_POLICY))
    report = {"status": "REVIEW_REQUIRED", "inputs": [], "secilc_sha256": tool_sha,
              "neverallow_disabled": False, "policy_loaded": False,
              "android_policy_verified": False, "runtime_verified": False,
              "safe_to_flash": False}
    total = 0
    with tempfile.TemporaryDirectory(prefix="r800-cil-") as tmp:
        root = Path(tmp)
        files = []
        for i, (path, expected) in enumerate(inputs):
            if not re.fullmatch(r"[0-9a-f]{64}", expected):
                raise ValueError("Expected lowercase SHA-256")
            raw = read_regular(Path(path), MAX_INPUT)
            if sha(raw) != expected:
                raise ValueError("CIL SHA-256 mismatch")
            total += len(raw)
            if total > MAX_TOTAL or b"\0" in raw:
                raise ValueError("CIL aggregate limit or invalid text")
            raw.decode("utf-8")
            dest = root / ("%02d.cil" % i)
            dest.write_bytes(raw)
            files.append(dest)
            report["inputs"].append({"index": i, "sha256": expected, "bytes": len(raw)})
        policy, contexts = root/"policy", root/"file_contexts"
        result = subprocess.run([str(tool), "-M", "true", "-c", "31",
                                 "-o", str(policy), "-f", str(contexts),
                                 *map(str, files)], cwd=root, capture_output=True,
                                timeout=90, check=False)
        report["compiler_exit_code"] = result.returncode
        report["diagnostic"] = result.stderr[-8192:].decode("utf-8", "replace")
        if result.returncode == 0:
            blob = read_regular(policy, MAX_POLICY)
            report.update(header(blob), policy_sha256=sha(blob), policy_bytes=len(blob),
                          status="CIL_COMPILED_STATIC_ONLY")
        if sha(read_regular(tool, MAX_POLICY)) != tool_sha:
            raise ValueError("Compiler changed during audit")
    return report


FIXTURE = """(class file (read write))
(classorder (file))
(sid kernel)
(sidorder (kernel))
(user system_u)
(role object_r)
(type fixture_t)
(type forbidden_t)
(roletype object_r fixture_t)
(roletype object_r forbidden_t)
(userrole system_u object_r)
(sensitivity s0)
(sensitivityorder (s0))
(level low (s0))
(levelrange low_low (low low))
(userlevel system_u low)
(userrange system_u low_low)
(sidcontext kernel (system_u object_r fixture_t low_low))
(allow fixture_t fixture_t (file (read)))
(neverallow fixture_t forbidden_t (file (write)))
"""


def fixture(tool):
    with tempfile.TemporaryDirectory(prefix="r800-cil-fixture-") as tmp:
        root = Path(tmp)
        base = root/"base.cil"
        conflict = root/"conflict.cil"
        base.write_text(FIXTURE, encoding="utf-8")
        conflict.write_text("(allow fixture_t forbidden_t (file (write)))\n", encoding="utf-8")
        first = (base, sha(base.read_bytes()))
        good = compile_cil([first], tool)
        bad = compile_cil([first, (conflict, sha(conflict.read_bytes()))], tool)
        passed = (good["status"] == "CIL_COMPILED_STATIC_ONLY" and
                  bad["compiler_exit_code"] != 0 and
                  "neverallow" in bad["diagnostic"].lower())
        return {"status": "SYNTHETIC_CIL_NEVERALLOW_PASS" if passed else "REVIEW_REQUIRED",
                "allowed": good, "forbidden": bad, "production_policy": False,
                "policy_loaded": False, "safe_to_flash": False}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--tool", type=Path, default=shutil.which("secilc"))
    p.add_argument("--input", nargs=2, action="append", metavar=("FILE", "SHA256"))
    p.add_argument("--fixture", action="store_true")
    p.add_argument("--report", type=Path, required=True)
    a = p.parse_args()
    if not a.tool or bool(a.input) == a.fixture:
        p.error("Specify compiler and exactly one of --fixture or --input")
    try:
        report = fixture(a.tool) if a.fixture else compile_cil(a.input, a.tool)
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        report = {"status": "REVIEW_REQUIRED", "reason": str(exc), "safe_to_flash": False}
    with a.report.open("x", encoding="utf-8") as f:
        json.dump(report, f, indent=2, sort_keys=True)
        f.write("\n")
    print(report["status"])
    return 0 if report["status"] in ("CIL_COMPILED_STATIC_ONLY", "SYNTHETIC_CIL_NEVERALLOW_PASS") else 2


if __name__ == "__main__":
    raise SystemExit(main())
