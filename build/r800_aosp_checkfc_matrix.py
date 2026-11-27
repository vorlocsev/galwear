#!/usr/bin/env python3
"""Run actual source-built AOSP checkfc against selected stock policy contexts."""
import argparse
import json
from pathlib import Path
import subprocess
import tempfile

from r800_android_init_dependencies import regular
from r800_android_userspace_preflight import read_regular
from r800_android_sepolicy_audit import POLICY_PATHS, header
from r800_donor_cil_compile import audit_checkfc, sha, MAX_POLICY, MAX_INPUT

PARTITIONS = {"system": "plat", "vendor": "vendor", "system_ext": "system_ext",
              "product": "product", "odm": "odm"}
KINDS = {"file": "file_contexts", "property": "property_contexts",
         "service": "service_contexts", "hwservice": "hwservice_contexts",
         "vndservice": "vndservice_contexts"}
REQUIRED = {"file", "property", "service", "hwservice"}


def audit(product, tool):
    product = product.resolve(strict=True)
    tool = tool.resolve(strict=True)
    tool_sha = sha(read_regular(tool, MAX_POLICY))
    policy_path = next((path for path in POLICY_PATHS if regular(product, path) is not None), None)
    if policy_path is None:
        raise ValueError("No source-built precompiled policy")
    blob = read_regular(regular(product, policy_path), MAX_POLICY)
    info = header(blob)
    rows = []
    present = set()
    with tempfile.TemporaryDirectory(prefix="galwear-aosp-checkfc-") as tmp:
        scratch = Path(tmp)
        policy = scratch/"policy"
        policy.write_bytes(blob)
        for partition, stem in PARTITIONS.items():
            for kind, suffix in KINDS.items():
                rel = partition + "/etc/selinux/" + stem + "_" + suffix
                source = regular(product, rel)
                if source is None:
                    rows.append({"path": rel, "kind": kind, "status": "NOT_PRESENT"})
                    continue
                raw = read_regular(source, MAX_INPUT)
                copy = scratch/("context-%d" % len(rows))
                copy.write_bytes(raw)
                result = audit_checkfc(policy, tool, tool_sha, [(kind, copy, sha(raw))])
                row = result["checks"][0]
                rows.append({"path": rel, **row})
                if row["status"] == "PASS":
                    present.add(kind)
        negative = scratch/"negative.contexts"
        negative.write_text("/galwear_checkfc_negative u:object_r:galwear_checkfc_nonexistent_type_9c3a17:s0\n")
        rejected = audit_checkfc(policy, tool, tool_sha,
                                 [("file", negative, sha(negative.read_bytes()))])["checks"][0]
        if sha(read_regular(regular(product, policy_path), MAX_POLICY)) != sha(blob):
            raise ValueError("Original policy changed")
        if sha(read_regular(tool, MAX_POLICY)) != tool_sha:
            raise ValueError("checkfc changed")
    missing = sorted(REQUIRED - present)
    complete = (not missing and not any(row["status"] == "REVIEW_REQUIRED" for row in rows)
                and rejected["exit_code"] == 1)
    return {"status": "AOSP_CHECKFC_STOCK_CONTEXTS_ONLY" if complete else "REVIEW_REQUIRED",
            "policy_path": policy_path, "policy_sha256": sha(blob), **info,
            "checkfc_sha256": tool_sha, "checks": rows, "missing_required_modes": missing,
            "negative_unknown_type": rejected, "vndservice_present": "vndservice" in present,
            "donor_policy_verified": False, "all_contexts_verified": False,
            "domain_transitions_verified": False, "policy_loaded": False, "safe_to_flash": False}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--product-out", type=Path, required=True)
    p.add_argument("--checkfc", type=Path, required=True)
    p.add_argument("--report", type=Path, required=True)
    a = p.parse_args()
    try:
        report = audit(a.product_out, a.checkfc)
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as exc:
        report = {"status": "REVIEW_REQUIRED", "reason": str(exc), "safe_to_flash": False}
    with a.report.open("x", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2, sort_keys=True)
        stream.write("\n")
    print(report["status"])
    return 0 if report["status"] == "AOSP_CHECKFC_STOCK_CONTEXTS_ONLY" else 2


if __name__ == "__main__":
    raise SystemExit(main())
