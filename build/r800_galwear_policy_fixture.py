#!/usr/bin/env python3
"""Non-production GalWear client policy preflight, separate from stock reports."""
import argparse
import json
from pathlib import Path
import subprocess
import tempfile

from r800_android_sepolicy_audit import audit, MAX_POLICY, sha
from r800_android_rootfs_preflight import snapshot
from r800_android_init_dependencies import regular

DOMAIN = "galwear_property_client"
LABEL = "u:object_r:galwear_property_client_exec:s0"
PROPERTIES = {
    "debug.galwear.service": "u:object_r:galwear_fixture_prop:s0",
    "ro.galwear.service.fixture": "u:object_r:galwear_fixture_prop:s0",
    "debug.galwear.denied": "u:object_r:galwear_denied_prop:s0",
    "ro.property_service.version": "u:object_r:galwear_protocol_prop:s0",
}
FILE = "/system/bin/galwear_property_client"
SERVICE = "/system/bin/galwear_property_service"
SERVICE_LABEL = "u:object_r:init_exec:s0"


def rows(data):
    return [line.split() for line in data.splitlines()
            if line.strip() and not line.lstrip().startswith("#")]


def verify_overlay(private, fixture):
    prop = rows((fixture / "property_contexts").read_text())
    fc = rows((fixture / "file_contexts").read_text())
    if sorted(prop) != sorted([[key, value, "exact", "string"] for key, value in PROPERTIES.items()]):
        raise ValueError("Unexpected fixture property mapping")
    if sorted(fc) != sorted([[FILE, LABEL], [SERVICE, SERVICE_LABEL]]):
        raise ValueError("Unexpected fixture executable mapping")
    for name, keys in (("file_contexts", {FILE, SERVICE}), ("property_contexts", set(PROPERTIES))):
        if any(row[0] in keys for row in rows((private / name).read_text())):
            raise ValueError("Existing exact platform context key: " + name)


def audit_fixture(product, checkfc, analyze):
    result = audit(product, checkfc)
    root = product.resolve(strict=True)
    policy = snapshot(regular(root, result["policy_path"]), MAX_POLICY)
    if sha(policy) != result["policy_sha256"]:
        raise ValueError("Policy changed")
    prop = snapshot(regular(root, "system/etc/selinux/plat_property_contexts"), 1024*1024)
    if sha(prop) != result["property_contexts_sha256"]["system/etc/selinux/plat_property_contexts"]:
        raise ValueError("Property contexts changed")
    for key, label in PROPERTIES.items():
        if [r for r in rows(prop.decode()) if r[0] == key] != [[key, label, "exact", "string"]]:
            raise ValueError("Fixture property mapping missing or ambiguous: " + key)
    fc = snapshot(regular(root, "system/etc/selinux/plat_file_contexts"), 4*1024*1024)
    for path, label in ((FILE, LABEL), (SERVICE, SERVICE_LABEL)):
        if [r for r in rows(fc.decode()) if r[0] == path] != [[path, label]]:
            raise ValueError("Fixture executable mapping missing or ambiguous: " + path)
    tool_sha = sha(snapshot(analyze, MAX_POLICY))
    with tempfile.TemporaryDirectory(prefix="galwear-fixture-policy-") as tmp:
        p, f = Path(tmp)/"sepolicy", Path(tmp)/"file_contexts"
        p.write_bytes(policy)
        f.write_bytes(fc)
        subprocess.run([str(checkfc.resolve(strict=True)), str(p), str(f)],
                       check=True, capture_output=True, timeout=30)
        out = subprocess.run([str(analyze.resolve(strict=True)), str(p), "permissive"],
                             check=True, capture_output=True, text=True, timeout=30)
        if DOMAIN in out.stdout.split():
            raise ValueError("Diagnostic client domain is permissive")
    if sha(snapshot(analyze, MAX_POLICY)) != tool_sha:
        raise ValueError("Policy analyzer changed")
    return {**result, "status": "GALWEAR_CLIENT_POLICY_STATIC_ONLY",
            "production_policy": False, "stock_policy": False,
            "client_domain": "u:r:"+DOMAIN+":s0",
            "client_not_listed_permissive": True, "analyze_sha256": tool_sha,
            "file_contexts_sha256": sha(fc), "fixture_property_contexts": PROPERTIES,
            "client_transition_tested": False, "client_mac_denial_tested": False,
            "safe_to_flash": False}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--private", type=Path)
    p.add_argument("--fixture", type=Path)
    for key in ("product-out", "checkfc", "analyze", "report"):
        p.add_argument("--"+key, type=Path)
    a = p.parse_args()
    try:
        if a.private and a.fixture and not any((a.product_out, a.checkfc, a.analyze, a.report)):
            verify_overlay(a.private, a.fixture)
            return 0
        if not all((a.product_out, a.checkfc, a.analyze, a.report)) or a.private or a.fixture:
            raise ValueError("Supply either overlay or complete policy audit inputs")
        report = audit_fixture(a.product_out, a.checkfc, a.analyze)
        rc = 0
    except (OSError, ValueError, KeyError, RuntimeError, subprocess.SubprocessError) as exc:
        report = {"status": "REJECT", "reason": str(exc), "safe_to_flash": False}
        rc = 2
    if a.report:
        a.report.write_text(json.dumps(report, indent=2, sort_keys=True)+"\n")
    print(report["status"])
    return rc

if __name__ == "__main__":
    raise SystemExit(main())
