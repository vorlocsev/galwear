#!/usr/bin/env python3
"""Audit stock Android file_contexts against the same precompiled policy."""
import argparse
import json
from pathlib import Path
import subprocess
import tempfile

from r800_android_sepolicy_audit import audit, MAX_POLICY, sha
from r800_android_rootfs_preflight import snapshot
from r800_android_init_dependencies import regular

FILE_CONTEXTS = (
    "system/etc/selinux/plat_file_contexts",
    "system_ext/etc/selinux/system_ext_file_contexts",
    "product/etc/selinux/product_file_contexts",
    "vendor/etc/selinux/vendor_file_contexts",
    "odm/etc/selinux/odm_file_contexts",
)
MAX_CONTEXTS = 4 * 1024 * 1024


def audit_files(product, checkfc, previous):
    root = product.resolve(strict=True)
    policy = audit(root, checkfc)
    if (previous.get("status") != "VIRT_ANDROID_STOCK_POLICY_LOAD_ONLY"
            or previous.get("stock_policy_loaded_reported") is not True
            or previous.get("enforcing_reported") is not True
            or previous.get("current_domain_reported") != "u:r:kernel:s0"
            or previous.get("policy_sha256") != policy["policy_sha256"]
            or previous.get("safe_to_flash") is not False):
        raise ValueError("Successful matching stock policy load required")
    blob = snapshot(regular(root, policy["policy_path"]), MAX_POLICY)
    if sha(blob) != policy["policy_sha256"]:
        raise ValueError("Policy changed after audit")
    hashes = {}
    with tempfile.TemporaryDirectory(prefix="galwear-file-contexts-") as tmp:
        temp = Path(tmp)
        binpath = temp / "sepolicy"
        binpath.write_bytes(blob)
        for i, rel in enumerate(FILE_CONTEXTS):
            source = regular(root, rel)
            if source is None:
                if i == 0:
                    raise ValueError("Platform file_contexts missing")
                continue
            data = snapshot(source, MAX_CONTEXTS)
            data.decode("utf-8")
            if b"\0" in data:
                raise ValueError("Binary or invalid file_contexts")
            path = temp / str(i)
            path.write_bytes(data)
            subprocess.run([str(checkfc.resolve(strict=True)), str(binpath), str(path)],
                           check=True, capture_output=True, timeout=30)
            hashes[rel] = sha(data)
    if sha(snapshot(checkfc, MAX_POLICY)) != policy["checkfc_sha256"]:
        raise ValueError("checkfc identity changed")
    return {"status": "ANDROID_FILE_CONTEXTS_STATIC_ONLY",
            "policy_sha256": policy["policy_sha256"],
            "generic_kernel_sha256": previous["generic_kernel_sha256"],
            "file_contexts_sha256": hashes, "checkfc_file_contexts_passed": True,
            "restorecon_tested": False, "init_domain_entered": False,
            "android_init_started": False, "safe_to_flash": False}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ("product-out", "checkfc", "stock-policy-report", "report"):
        p.add_argument("--" + name, type=Path, required=True)
    a = p.parse_args()
    try:
        previous = json.loads(snapshot(a.stock_policy_report, 262144))
        report = audit_files(a.product_out, a.checkfc, previous)
        rc = 0
    except (OSError, ValueError, TypeError, KeyError, RuntimeError, subprocess.SubprocessError) as exc:
        report = {"status": "REJECT", "reason": str(exc), "safe_to_flash": False}
        rc = 2
    a.report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(report["status"])
    return rc

if __name__ == "__main__":
    raise SystemExit(main())
