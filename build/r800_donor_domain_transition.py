#!/usr/bin/env python3
"""Offline necessary SELinux domain-transition rules, never load policy."""
import argparse
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

from r800_donor_cil_compile import compile_cil, FIXTURE, sha, MAX_POLICY
from r800_android_userspace_preflight import read_regular
from r800_android_sepolicy_audit import header

TYPE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}")


def evaluate(policy, tool, source, executable, target):
    if not all(TYPE.fullmatch(t) for t in (source, executable, target)):
        raise ValueError("Invalid SELinux type name")
    tool = Path(tool).resolve(strict=True)
    policy = Path(policy)
    tool_sha = sha(read_regular(tool, MAX_POLICY))
    blob = read_regular(policy, MAX_POLICY)
    header(blob)
    policy_sha = sha(blob)

    def query(args, pattern):
        result = subprocess.run([str(tool), *args, str(policy)], capture_output=True,
                                text=True, timeout=30, check=True)
        lines = result.stdout.splitlines()
        matches = [line.strip() for line in lines if re.fullmatch(pattern, line.strip())]
        return {"found": bool(matches), "matching_rules": matches[:20]}

    # Direct concrete type_transition only: attributes in allow rules may be
    # expanded by sesearch, but conditional rules cannot count as evidence.
    transition = query(["-T", "-s", source, "-t", executable, "-c", "process"],
                       rf"type_transition\s+{source}\s+{executable}:process\s+{target};")
    checks = [{"name": "type_transition", **transition}]
    for src, dst, klass, perm in (
            (source, target, "process", "transition"),
            (source, executable, "file", "execute"),
            (target, executable, "file", "entrypoint")):
        result = query(["--allow", "-s", src, "-t", dst, "-c", klass, "-p", perm],
                       r"allow\s+\S+\s+\S+:\S+\s+[^;]+;")
        checks.append({"name": perm, "source": src, "target": dst, "class": klass, **result})
    if sha(read_regular(policy, MAX_POLICY)) != policy_sha or sha(read_regular(tool, MAX_POLICY)) != tool_sha:
        raise ValueError("Policy or sesearch changed")
    return {"status": "DOMAIN_TRANSITION_RULES_ONLY" if all(c["found"] for c in checks)
            else "REVIEW_REQUIRED", "source": source, "executable": executable,
            "target": target, "checks": checks, "policy_sha256": policy_sha,
            "sesearch_sha256": tool_sha, "runtime_transition_verified": False,
            "all_permissions_verified": False, "policy_loaded": False, "safe_to_flash": False}


def fixture(compiler, tool):
    cil = FIXTURE.replace("(class file (read write))", "(class file (read write execute entrypoint))")
    cil = cil.replace("(classorder (file))", "(class process (transition))\n(classorder (file process))")
    cil += """
(type init_fixture_t)
(type hal_fixture_exec_t)
(type hal_fixture_t)
(type other_fixture_t)
(roletype object_r init_fixture_t)
(roletype object_r hal_fixture_exec_t)
(roletype object_r hal_fixture_t)
(roletype object_r other_fixture_t)
(typetransition init_fixture_t hal_fixture_exec_t process hal_fixture_t)
(allow init_fixture_t hal_fixture_t (process (transition)))
(allow init_fixture_t hal_fixture_exec_t (file (execute)))
(allow hal_fixture_t hal_fixture_exec_t (file (entrypoint)))
"""
    with tempfile.TemporaryDirectory(prefix="r800-transition-") as tmp:
        path = Path(tmp)/"fixture.cil"
        path.write_text(cil, encoding="utf-8")
        def probe(policy):
            good = evaluate(policy, tool, "init_fixture_t", "hal_fixture_exec_t", "hal_fixture_t")
            bad = evaluate(policy, tool, "init_fixture_t", "hal_fixture_exec_t", "other_fixture_t")
            return {"status": "SYNTHETIC_TRANSITION_RULES_PASS" if
                    good["status"] == "DOMAIN_TRANSITION_RULES_ONLY" and
                    bad["status"] == "REVIEW_REQUIRED" and
                    not bad["checks"][0]["found"] else "REVIEW_REQUIRED",
                    "positive": good, "negative": bad}
        compiled = compile_cil([(path, sha(path.read_bytes()))], compiler, policy_probe=probe)
        audit = compiled.get("policy_probe", {})
        return {"status": audit.get("status", "REVIEW_REQUIRED"), "compile": compiled,
                "production_policy": False, "policy_loaded": False, "safe_to_flash": False}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--fixture", action="store_true")
    p.add_argument("--compiler", type=Path, default=shutil.which("secilc"))
    p.add_argument("--sesearch", type=Path, default=shutil.which("sesearch"))
    p.add_argument("--policy", type=Path)
    p.add_argument("--policy-sha256")
    p.add_argument("--source")
    p.add_argument("--executable")
    p.add_argument("--target")
    p.add_argument("--report", type=Path, required=True)
    a = p.parse_args()
    try:
        if not a.sesearch:
            raise ValueError("sesearch required")
        if a.fixture:
            if not a.compiler or any((a.policy, a.policy_sha256, a.source, a.executable, a.target)):
                raise ValueError("Invalid fixture arguments")
            report = fixture(a.compiler, a.sesearch)
        else:
            if not all((a.policy, a.policy_sha256, a.source, a.executable, a.target)):
                raise ValueError("Explicit policy digest and three types required")
            blob = read_regular(a.policy, MAX_POLICY)
            if sha(blob) != a.policy_sha256:
                raise ValueError("Policy SHA-256 mismatch")
            with tempfile.TemporaryDirectory(prefix="r800-transition-policy-") as tmp:
                policy = Path(tmp)/"policy"
                policy.write_bytes(blob)
                report = evaluate(policy, a.sesearch, a.source, a.executable, a.target)
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        report = {"status": "REVIEW_REQUIRED", "reason": str(exc), "safe_to_flash": False}
    with a.report.open("x", encoding="utf-8") as f:
        json.dump(report, f, indent=2, sort_keys=True)
        f.write("\n")
    print(report["status"])
    return 0 if report["status"] in ("SYNTHETIC_TRANSITION_RULES_PASS", "DOMAIN_TRANSITION_RULES_ONLY") else 2


if __name__ == "__main__":
    raise SystemExit(main())
