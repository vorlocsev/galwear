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


def audit_context_labels(policy, checker, entries):
    """Verify literal context tokens only, not Android file regex or type attributes."""
    from r800_selinux_inventory import CONTEXT
    checker = Path(checker).resolve(strict=True)
    tool_sha = sha(read_regular(checker, MAX_POLICY))
    rows, labels = [], set()
    if not 1 <= len(entries) <= 16:
        raise ValueError("Expected 1..16 context files")
    for path, expected in entries:
        raw = read_regular(Path(path), MAX_INPUT)
        if sha(raw) != expected:
            raise ValueError("Context SHA-256 mismatch")
        count = 0
        for line in raw.decode("utf-8").splitlines():
            fields = line.split()
            if not fields or fields[0].startswith("#"):
                continue
            tokens = [value for value in fields[1:] if CONTEXT.fullmatch(value)]
            if len(tokens) != 1:
                raise ValueError("Expected one literal SELinux context per record")
            labels.add(tokens[0])
            count += 1
            if len(labels) > 512 or count > 65536:
                raise ValueError("Context inventory budget exceeded")
        rows.append({"sha256": expected, "records": count})
    if not labels:
        raise ValueError("No context labels")
    ordered = sorted(labels)
    policy_sha = sha(read_regular(policy, MAX_POLICY))
    run = subprocess.run([str(checker), str(policy), *ordered], capture_output=True,
                         text=True, timeout=30, check=False)
    lines = run.stdout.splitlines()
    if len(lines) != len(ordered) or any(line not in
            (f"{i} VALID", f"{i} INVALID") for i, line in enumerate(lines)):
        raise ValueError("Incomplete context checker response")
    invalid = [label for label, line in zip(ordered, lines) if line.endswith(" INVALID")]
    if run.returncode != (1 if invalid else 0):
        raise ValueError("Inconsistent context checker result")
    if sha(read_regular(checker, MAX_POLICY)) != tool_sha or sha(read_regular(policy, MAX_POLICY)) != policy_sha:
        raise ValueError("Context checker or policy changed")
    return {"status": "CONTEXT_LABELS_VALID_ONLY" if not invalid else "REVIEW_REQUIRED",
            "inputs": rows, "unique_labels": len(ordered), "invalid_labels": invalid,
            "checker_sha256": tool_sha, "policy_sha256": policy_sha,
            "android_checkfc_verified": False, "domain_transitions_verified": False,
            "policy_loaded": False, "safe_to_flash": False}


CHECKFC_MODES = {"file": [], "property": ["-p"], "service": ["-s"],
                 "hwservice": ["-l"], "vndservice": ["-v"]}


def audit_checkfc(policy, tool, expected_tool_sha, entries):
    """Use explicit AOSP host checkfc on the same temporary compiled policy."""
    if not 1 <= len(entries) <= 32:
        raise ValueError("Expected 1..32 checkfc context files")
    tool = Path(tool).resolve(strict=True)
    if not re.fullmatch(r"[0-9a-f]{64}", expected_tool_sha):
        raise ValueError("Expected checkfc SHA-256")
    if sha(read_regular(tool, MAX_POLICY)) != expected_tool_sha:
        raise ValueError("checkfc SHA-256 mismatch")
    policy_sha = sha(read_regular(policy, MAX_POLICY))
    rows = []
    total = 0
    seen = set()
    with tempfile.TemporaryDirectory(prefix="r800-checkfc-") as tmp:
        root = Path(tmp)
        for i, (kind, path, expected) in enumerate(entries):
            if kind not in CHECKFC_MODES:
                raise ValueError("Unsupported checkfc context kind")
            raw = read_regular(Path(path), MAX_INPUT)
            if sha(raw) != expected:
                raise ValueError("checkfc context SHA-256 mismatch")
            total += len(raw)
            if total > MAX_TOTAL or b"\0" in raw:
                raise ValueError("checkfc context size or text invalid")
            raw.decode("utf-8")
            if (kind, expected) in seen:
                raise ValueError("Duplicate checkfc context input")
            seen.add((kind, expected))
            dest = root / ("%02d.contexts" % i)
            dest.write_bytes(raw)
            result = subprocess.run([str(tool), *CHECKFC_MODES[kind], str(policy),
                                     str(dest)], cwd=root, capture_output=True,
                                    timeout=30, check=False)
            rows.append({"kind": kind, "sha256": expected, "bytes": len(raw),
                         "exit_code": result.returncode,
                         "status": "PASS" if result.returncode == 0 else "REVIEW_REQUIRED",
                         "diagnostic": result.stderr[-8192:].decode("utf-8", "replace")})
            if sha(read_regular(policy, MAX_POLICY)) != policy_sha:
                raise ValueError("Policy changed during checkfc")
            if sha(read_regular(tool, MAX_POLICY)) != expected_tool_sha:
                raise ValueError("checkfc changed during audit")
    return {"status": "CHECKFC_SELECTED_CONTEXTS_ONLY" if all(row["status"] == "PASS"
            for row in rows) else "REVIEW_REQUIRED", "policy_sha256": policy_sha,
            "checkfc_sha256": expected_tool_sha, "checks": rows,
            "tool_source_authenticity_verified": False, "all_contexts_verified": False,
            "policy_loaded": False, "runtime_verified": False, "safe_to_flash": False}


def compile_cil(inputs, tool, checker=None, context_entries=(), checkfc=None,
                checkfc_sha=None, checkfc_entries=(), policy_probe=None):
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
            if checker is not None:
                report["context_audit"] = audit_context_labels(policy, checker, context_entries)
                if report["context_audit"]["status"] != "CONTEXT_LABELS_VALID_ONLY":
                    report["status"] = "REVIEW_REQUIRED"
            if checkfc is not None:
                report["checkfc_audit"] = audit_checkfc(policy, checkfc, checkfc_sha, checkfc_entries)
                if report["checkfc_audit"]["status"] != "CHECKFC_SELECTED_CONTEXTS_ONLY":
                    report["status"] = "REVIEW_REQUIRED"
            if policy_probe is not None:
                report["policy_probe"] = policy_probe(policy)
                if report["policy_probe"]["status"] == "REVIEW_REQUIRED":
                    report["status"] = "REVIEW_REQUIRED"
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


def fixture(tool, checker=None):
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
        report = {"status": "SYNTHETIC_CIL_NEVERALLOW_PASS" if passed else "REVIEW_REQUIRED",
                  "allowed": good, "forbidden": bad, "production_policy": False,
                  "policy_loaded": False, "safe_to_flash": False}
        if checker is not None:
            valid = root/"valid.contexts"
            invalid = root/"invalid.contexts"
            valid.write_text("/vendor/bin/fixture system_u:object_r:fixture_t:s0\n")
            invalid.write_text("/vendor/bin/fixture system_u:object_r:unknown_t:s0\n")
            positive = compile_cil([first], tool, checker, [(valid, sha(valid.read_bytes()))])
            negative = compile_cil([first], tool, checker, [(invalid, sha(invalid.read_bytes()))])
            report["context_positive"], report["context_negative"] = positive, negative
            if (not passed or positive["status"] != "CIL_COMPILED_STATIC_ONLY" or
                    negative["status"] != "REVIEW_REQUIRED" or
                    negative.get("context_audit", {}).get("invalid_labels") !=
                    ["system_u:object_r:unknown_t:s0"]):
                report["status"] = "REVIEW_REQUIRED"
        return report


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--tool", type=Path, default=shutil.which("secilc"))
    p.add_argument("--input", nargs=2, action="append", metavar=("FILE", "SHA256"))
    p.add_argument("--fixture", action="store_true")
    p.add_argument("--context-checker", type=Path)
    p.add_argument("--contexts", nargs=2, action="append", metavar=("FILE", "SHA256"))
    p.add_argument("--checkfc", type=Path)
    p.add_argument("--checkfc-sha256")
    p.add_argument("--checkfc-context", nargs=3, action="append", metavar=("KIND", "FILE", "SHA256"))
    p.add_argument("--report", type=Path, required=True)
    a = p.parse_args()
    if not a.tool or bool(a.input) == a.fixture:
        p.error("Specify compiler and exactly one of --fixture or --input")
    if (a.fixture and a.contexts) or (not a.fixture and bool(a.context_checker) != bool(a.contexts)):
        p.error("Explicit contexts require the context checker; fixture supplies its own")
    if len({bool(a.checkfc), bool(a.checkfc_sha256), bool(a.checkfc_context)}) != 1 or (a.fixture and a.checkfc):
        p.error("Provide checkfc, its SHA-256 and context inputs together outside fixture mode")
    try:
        report = fixture(a.tool, a.context_checker) if a.fixture else compile_cil(
            a.input, a.tool, a.context_checker, a.contexts or (), a.checkfc,
            a.checkfc_sha256, a.checkfc_context or ())
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        report = {"status": "REVIEW_REQUIRED", "reason": str(exc), "safe_to_flash": False}
    with a.report.open("x", encoding="utf-8") as f:
        json.dump(report, f, indent=2, sort_keys=True)
        f.write("\n")
    print(report["status"])
    return 0 if report["status"] in ("CIL_COMPILED_STATIC_ONLY", "SYNTHETIC_CIL_NEVERALLOW_PASS") else 2


if __name__ == "__main__":
    raise SystemExit(main())
