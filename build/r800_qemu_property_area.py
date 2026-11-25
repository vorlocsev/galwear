#!/usr/bin/env python3
"""Static source-built Bionic property-area experiment; no property service."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

from r800_qemu_guest_abi import read_bounded_json, verify_baseline
from r800_qemu_property_kernel import verify_config
from r800_qemu_system_init import run as boot
from r800_qemu_user_init import EXPECTED, HEARTBEAT_PREFIX
from r800_initramfs_spec import validate_init

MARKERS = [
    b"r800-property-area: init=PASS add=PASS",
    b"r800-property-area: separate-exec read=ready",
    b"r800-property-area: wait=PASS updated-read=PASS serial-changed=PASS",
    b"r800-property-area: PASS service=not-started",
]

def inspect_console(log):
    lines = log.replace(b"\r\n", b"\n").splitlines()
    if [line for line in lines if line.startswith(b"r800-property-area:")] != MARKERS:
        raise ValueError("Unexpected property area diagnostic sequence")
    startup = EXPECTED.rstrip(b"\n")
    if lines.count(startup) != 1 or lines.index(startup) >= lines.index(MARKERS[0]):
        raise ValueError("Property area before startup")
    if any(line.startswith(HEARTBEAT_PREFIX) for line in lines[:lines.index(MARKERS[-1])]):
        raise ValueError("Heartbeat before property area completion")
    return {"bionic_area_init_reported": True, "property_add_reported": True,
            "separate_exec_read_reported": True, "property_update_wait_reported": True,
            "property_service_started": False, "android_init_started": False,
            "android_sepolicy_tested": False}

def snapshot(path, cap):
    if path.is_symlink() or not path.is_file():
        raise ValueError("Invalid fixture input")
    with path.open("rb") as f:
        data = f.read(cap + 1)
    if not 0 < len(data) <= cap:
        raise ValueError("Fixture size outside bounds")
    return data

def sha(data):
    return hashlib.sha256(data).hexdigest()

def verify_policy_run(path, kernel_sha, policy_sha):
    r = read_bounded_json(path)
    p = r.get("policy_compile_evidence")
    if (r.get("status") != "VIRT_SELINUX_FIXTURE_ONLY"
            or r.get("generic_kernel_sha256") != kernel_sha
            or r.get("same_dac_allow_deny_reported") is not True
            or r.get("enforcing_reported") is not True
            or r.get("safe_to_flash") is not False
            or not isinstance(p, dict) or p.get("policy_sha256") != policy_sha):
        raise ValueError("Successful same-kernel same-policy SELinux fixture required")

def verify_embedded(init, policy, info):
    data = snapshot(init, 16 * 1024 * 1024)
    if data.count(policy) != 1 or data.count(info) != 1:
        raise ValueError("Embedded property fixtures missing or ambiguous")
    return sha(data)

def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ("init", "compile-evidence", "kernel", "baseline", "config-evidence",
                 "policy-run", "policy-bin", "property-info", "out-dir", "report"):
        p.add_argument("--" + name, type=Path, required=True)
    a = p.parse_args()
    try:
        kernel_sha = verify_baseline(a.baseline, a.kernel)
        verify_config(a.config_evidence, kernel_sha)
        policy = snapshot(a.policy_bin, 1024 * 1024)
        info = snapshot(a.property_info, 65536)
        verify_policy_run(a.policy_run, kernel_sha, sha(policy))
        init_sha = verify_embedded(a.init, policy, info)
        if validate_init(a.init)["sha256"] != init_sha:
            raise ValueError("Init changed before boot")
        evidence = boot(a.init, a.compile_evidence, a.kernel, a.out_dir)
        if evidence["generic_kernel_sha256"] != kernel_sha or evidence["init_sha256"] != init_sha:
            raise ValueError("Boot identity mismatch")
        report = {**evidence, **inspect_console((a.out_dir / "generic-console.log").read_bytes()),
                  "status": "VIRT_BIONIC_PROPERTY_AREA_ONLY", "policy_sha256": sha(policy),
                  "property_info_sha256": sha(info), "safe_to_flash": False}
        rc = 0
    except (OSError, ValueError, IndexError, KeyError, EOFError, subprocess.SubprocessError) as exc:
        report = {"status": "REJECT", "reason": str(exc), "safe_to_flash": False,
                  "property_service_started": False}
        rc = 2
    a.report.write_text(json.dumps(report, indent=2) + "\n")
    print(report["status"])
    return rc

if __name__ == "__main__":
    raise SystemExit(main())
