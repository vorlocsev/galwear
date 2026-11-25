#!/usr/bin/env python3
"""Boot pre-policy property-kernel diagnostics, never claim Android policy or service."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

from r800_qemu_guest_abi import verify_baseline, read_bounded_json
from r800_qemu_system_init import run as boot
from r800_qemu_user_init import EXPECTED, HEARTBEAT_PREFIX

MARKERS = [
    b"r800-property-kernel: unix stream=PASS peercred=PASS",
    b"r800-property-kernel: selinuxfs=PASS enforce=1 policy-not-loaded-by-probe",
    b"r800-property-kernel: tmpfs trusted-xattr=PASS security-label-io=PASS",
    b"r800-property-kernel: PASS",
]


def inspect_console(log: bytes) -> dict:
    lines = log.replace(b"\r\n", b"\n").splitlines()
    found = [line for line in lines if line.startswith(b"r800-property-kernel:")]
    if found != MARKERS:
        raise ValueError("Unexpected property kernel diagnostic sequence")
    startup = EXPECTED.rstrip(b"\n")
    if lines.count(startup) != 1 or lines.index(startup) >= lines.index(MARKERS[0]):
        raise ValueError("Property diagnostics before PID1 startup")
    if any(line.startswith(HEARTBEAT_PREFIX) for line in lines[:lines.index(MARKERS[-1])]):
        raise ValueError("Heartbeat before property kernel diagnostic completion")
    return {"unix_stream_roundtrip_reported": True, "unix_peer_credentials_reported": True,
            "selinuxfs_mount_reported": True, "selinux_enforce_value_reported": 1,
            "tmpfs_trusted_xattr_roundtrip_reported": True, "security_label_io_reported": True,
            "effective_selinux_label_verified": False, "selinux_policy_loaded": False,
            "selinux_access_control_tested": False, "property_service_started": False}


def verify_config(path: Path, digest: str) -> dict:
    config = read_bounded_json(path)
    if (config.get("status") != "VIRT_CONFIG_STATIC_ONLY"
            or config.get("profile") != "property"
            or config.get("compiled_kernel_sha256") != digest
            or config.get("safe_to_flash") is not False):
        raise ValueError("Matching compiled property profile evidence required")
    return config


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    for name in ("init", "compile-evidence", "kernel", "baseline", "config-evidence",
                 "out-dir", "report"):
        p.add_argument("--" + name, required=True, type=Path)
    a = p.parse_args()
    try:
        digest = verify_baseline(a.baseline, a.kernel)
        cfg = verify_config(a.config_evidence, digest)
        evidence = boot(a.init, a.compile_evidence, a.kernel, a.out_dir)
        if evidence["generic_kernel_sha256"] != digest:
            raise ValueError("Kernel changed after baseline")
        report = {**evidence, **inspect_console((a.out_dir / "generic-console.log").read_bytes()),
                  "status": "VIRT_PROPERTY_KERNEL_PREPOLICY_ONLY",
                  "profile": "property", "config_sha256": cfg["config_sha256"],
                  "safe_to_flash": False}
        rc = 0
    except (OSError, ValueError, KeyError, IndexError, EOFError, subprocess.SubprocessError) as exc:
        report = {"status": "REJECT", "reason": str(exc), "safe_to_flash": False,
                  "selinux_policy_loaded": False, "property_service_started": False}
        rc = 2
    a.report.write_text(json.dumps(report, indent=2) + "\n")
    print(report["status"])
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
