#!/usr/bin/env python3
"""Read-only compiled-policy feasibility audit for kernel-domain rootfs relabel.

This tests necessary permissions, not sufficient conditions for restorecon.
A stock policy designed for mounted, pre-labeled partitions may reject this
ramdisk experiment. Do not add broad kernel permissions to make it pass.
"""
import argparse
import json
from pathlib import Path
import re
import subprocess

from r800_android_sepolicy_audit import audit, MAX_POLICY, sha
from r800_android_rootfs_preflight import snapshot
from r800_android_init_dependencies import regular

# Required on ordinary rootfs objects for the current kernel-domain strategy.
# This is not a complete model of APEX file labels or filesystem associate.
CHECKS = (
    ("rootfs", "file", "relabelfrom"),
    ("init_exec", "file", "relabelto"),
    ("rootfs", "dir", "relabelfrom"),
    ("system_file", "dir", "relabelto"),
    ("system_file", "file", "relabelto"),
)


def allow_query(policy, target, klass, permission, sesearch="sesearch"):
    result = subprocess.run([sesearch, "--allow", "-s", "kernel", "-t", target,
                             "-c", klass, "-p", permission, str(policy)],
                            check=True, capture_output=True, text=True, timeout=30)
    # sesearch resolves source/target attributes. Conditional rules are not
    # sufficient evidence of an unconditional allow.
    rules = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    matching = [rule for rule in rules if re.fullmatch(r"allow\s+\S+\s+\S+:\S+\s+[^;]+;", rule)]
    return {"target": target, "class": klass, "permission": permission,
            "unconditional_allow_found": bool(matching), "matching_rules": matching[:20]}


def evaluate(policy, sesearch="sesearch"):
    results = [allow_query(policy, target, klass, perm, sesearch)
               for target, klass, perm in CHECKS]
    missing = [f"kernel {r['target']}:{r['class']} {r['permission']}"
               for r in results if not r["unconditional_allow_found"]]
    return {"status": "ROOTFS_RELABEL_POLICY_PREREQUISITES_ONLY" if not missing else
            "ROOTFS_RELABEL_POLICY_BLOCKED", "checks": results,
            "missing_unconditional_permissions": missing,
            "full_relabel_feasibility_proven": False,
            "recommended_alternative": "prelabeled partition images, not broader kernel allow rules",
            "safe_to_flash": False}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ("product-out", "checkfc", "report"):
        p.add_argument("--"+name, required=True, type=Path)
    p.add_argument("--sesearch", default="sesearch")
    a = p.parse_args()
    try:
        evidence = audit(a.product_out, a.checkfc)
        policy = regular(a.product_out.resolve(strict=True), evidence["policy_path"])
        if sha(snapshot(policy, MAX_POLICY)) != evidence["policy_sha256"]:
            raise ValueError("Policy changed after static audit")
        report = evaluate(policy, a.sesearch)
        if sha(snapshot(policy, MAX_POLICY)) != evidence["policy_sha256"]:
            raise ValueError("Policy changed during permission queries")
        report["policy_sha256"] = evidence["policy_sha256"]
        rc = 0 if report["status"] == "ROOTFS_RELABEL_POLICY_PREREQUISITES_ONLY" else 3
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        report = {"status": "REJECT", "reason": str(exc), "safe_to_flash": False}
        rc = 2
    a.report.write_text(json.dumps(report, indent=2, sort_keys=True)+"\n")
    print(report["status"])
    return rc

if __name__ == "__main__":
    raise SystemExit(main())
