#!/usr/bin/env python3
"""Acceptance gate for synthetic SELinux policy, never Android sepolicy."""
import argparse
import json
from pathlib import Path
import subprocess

from r800_qemu_guest_abi import read_bounded_json, verify_baseline
from r800_qemu_property_kernel import verify_config
from r800_qemu_system_init import run as boot
from r800_qemu_user_init import EXPECTED, HEARTBEAT_PREFIX

MARKERS = [
    b"r800-policy: load=PASS enforce=1 fixture-only",
    b"r800-policy: label=PASS same-dac=PASS",
    b"r800-policy: allowed-read=PASS",
    b"r800-policy: denied-read=EACCES enforce=1",
    b"r800-policy: PASS",
]

def inspect_console(log):
    lines = log.replace(b"\r\n", b"\n").splitlines()
    if [line for line in lines if line.startswith(b"r800-policy:")] != MARKERS:
        raise ValueError("Unexpected SELinux diagnostic sequence")
    startup = EXPECTED.rstrip(b"\n")
    if lines.count(startup) != 1 or lines.index(startup) >= lines.index(MARKERS[0]):
        raise ValueError("SELinux markers outside startup window")
    if any(line.startswith(HEARTBEAT_PREFIX) for line in lines[:lines.index(MARKERS[-1])]):
        raise ValueError("Heartbeat before SELinux completion")
    return {"selinux_fixture_loaded_reported": True, "enforcing_reported": True,
            "same_dac_allow_deny_reported": True, "effective_label_reported": True,
            "android_sepolicy_tested": False, "property_service_started": False}

def verify_prepolicy(path, digest):
    r = read_bounded_json(path)
    if (r.get("status") != "VIRT_PROPERTY_KERNEL_PREPOLICY_ONLY"
            or r.get("generic_kernel_sha256") != digest
            or r.get("unix_peer_credentials_reported") is not True
            or r.get("security_label_io_reported") is not True
            or r.get("safe_to_flash") is not False):
        raise ValueError("Matching pre-policy baseline required")

def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ("init", "compile-evidence", "kernel", "baseline", "config-evidence",
                 "prepolicy", "policy-evidence", "out-dir", "report"):
        p.add_argument("--" + name, type=Path, required=True)
    a = p.parse_args()
    try:
        digest = verify_baseline(a.baseline, a.kernel)
        verify_config(a.config_evidence, digest)
        verify_prepolicy(a.prepolicy, digest)
        policy = read_bounded_json(a.policy_evidence)
        if (policy.get("status") != "VIRT_TEST_POLICY_COMPILED_ONLY"
                or policy.get("policy_version") != 31 or policy.get("production_policy") is not False
                or policy.get("safe_to_flash") is not False):
            raise ValueError("Invalid compiled fixture policy evidence")
        evidence = boot(a.init, a.compile_evidence, a.kernel, a.out_dir)
        if evidence["generic_kernel_sha256"] != digest:
            raise ValueError("Kernel digest changed")
        report = {**evidence, **inspect_console((a.out_dir / "generic-console.log").read_bytes()),
                  "status": "VIRT_SELINUX_FIXTURE_ONLY", "policy_compile_evidence": policy,
                  "production_policy": False, "safe_to_flash": False}
        rc = 0
    except (OSError, ValueError, KeyError, IndexError, EOFError, subprocess.SubprocessError) as exc:
        report = {"status": "REJECT", "reason": str(exc), "safe_to_flash": False}
        rc = 2
    a.report.write_text(json.dumps(report, indent=2) + "\n")
    print(report["status"])
    return rc

if __name__ == "__main__":
    raise SystemExit(main())
