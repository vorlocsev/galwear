#!/usr/bin/env python3
"""Boot only the canonical Android rootfs preflight archive on generic virt.

No Android handover, no policy loading, no arbitrary initrd, disks or NIC.
"""
import argparse
import json
from pathlib import Path
import subprocess

from r800_android_rootfs_preflight import prepare, snapshot, sha, CAP
from r800_qemu_guest_abi import verify_baseline, read_bounded_json
from r800_qemu_property_kernel import verify_config
from r800_qemu_selinux_policy import verify_prepolicy
from r800_qemu_system_init import kernel_bytes, observe_boot
from r800_qemu_user_init import EXPECTED, HEARTBEAT_PREFIX

MARKERS = [
    b"r800-rootfs: proc=PASS sys=PASS dev=PASS data=PASS",
    b"r800-rootfs: contexts-readable=PASS socket-directory=PASS",
    b"r800-rootfs: PASS android-init=not-started policy=not-loaded",
]


def inspect_console(log):
    lines = log.replace(b"\r\n", b"\n").splitlines()
    if [line for line in lines if line.startswith(b"r800-rootfs:")] != MARKERS:
        raise ValueError("Unexpected rootfs preflight diagnostic sequence")
    startup = EXPECTED.rstrip(b"\n")
    if lines.count(startup) != 1 or lines.index(startup) >= lines.index(MARKERS[0]):
        raise ValueError("Rootfs markers outside startup window")
    if any(line.startswith(HEARTBEAT_PREFIX) for line in lines[:lines.index(MARKERS[-1])]):
        raise ValueError("Heartbeat before rootfs preflight completion")
    if any(line.startswith((b"r800-property-service:", b"r800-property-client:",
                            b"r800-property-area:", b"r800-policy:")) for line in lines):
        raise ValueError("Unexpected Android service or policy diagnostics")
    return {"ram_mounts_reported": True, "property_contexts_readable_reported": True,
            "socket_directory_ready_reported": True, "android_init_started": False,
            "property_service_started": False, "selinux_policy_loaded": False}


def verify_archive(existing, canonical):
    if snapshot(existing, CAP) != canonical:
        raise ValueError("Archive differs from canonical reconstruction")


def command(image, archive):
    return ["qemu-system-aarch64", "-machine", "virt,gic-version=3,accel=tcg",
            "-cpu", "cortex-a53", "-smp", "2", "-m", "512M", "-nodefaults",
            "-no-reboot", "-display", "none", "-monitor", "none", "-serial", "stdio",
            "-nic", "none", "-kernel", str(image.resolve()),
            "-initrd", str(archive.resolve()),
            "-append", "console=ttyAMA0 rdinit=/init ro loglevel=7 panic=-1"]


def run(a):
    digest = verify_baseline(a.baseline, a.kernel)
    cfg = verify_config(a.config_evidence, digest)
    verify_prepolicy(a.prepolicy, digest)
    raw = kernel_bytes(a.kernel)
    if sha(raw) != digest:
        raise ValueError("Kernel changed since baseline")
    archive, report = prepare(a.staged, a.product_out, a.init, a.readelf)
    verify_archive(a.archive, archive)
    a.out_dir.mkdir(exist_ok=False)
    image = a.out_dir / "generic-Image"
    cpio = a.out_dir / "preflight.cpio"
    image.write_bytes(raw)
    cpio.write_bytes(archive)
    if kernel_bytes(image) != raw:
        raise ValueError("Kernel staging mismatch")
    verify_archive(cpio, archive)
    version = subprocess.run(["qemu-system-aarch64", "--version"], check=True,
                             capture_output=True, text=True, timeout=5).stdout.splitlines()[0]
    log = a.out_dir / "generic-console.log"
    observed = observe_boot(command(image, cpio), log)
    verify_archive(cpio, archive)
    if sha(kernel_bytes(image)) != digest:
        raise ValueError("Kernel changed during boot")
    return {**report, **observed, **inspect_console(log.read_bytes()),
            "status": "VIRT_ANDROID_ROOTFS_PREFLIGHT_ONLY",
            "canonical_archive_verified": True, "profile": "property",
            "generic_kernel_sha256": digest, "config_sha256": cfg["config_sha256"],
            "qemu_version": version, "namespace_resolution_tested": False,
            "android_sepolicy_tested": False, "exynos9110_emulated": False,
            "device_contacted": False, "safe_to_flash": False}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ("staged", "product-out", "init", "archive", "kernel",
                 "baseline", "config-evidence", "prepolicy", "out-dir", "report"):
        p.add_argument("--" + name, required=True, type=Path)
    p.add_argument("--readelf", default="readelf")
    a = p.parse_args()
    try:
        report = run(a)
        rc = 0
    except (OSError, ValueError, TypeError, KeyError, IndexError, EOFError,
            RuntimeError, subprocess.SubprocessError) as exc:
        report = {"status": "REJECT", "reason": str(exc),
                  "android_init_started": False, "property_service_started": False,
                  "safe_to_flash": False}
        rc = 2
    a.report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(report["status"])
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
