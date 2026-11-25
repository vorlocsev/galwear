#!/usr/bin/env python3
"""Load audited stock Android MLS policy in a separate, minimal virt guest.

The previous expanded rootfs is evidence only, not mounted in this test.
No relabel, context transition, Android service or hardware handover.
"""
import argparse
import json
from pathlib import Path
import subprocess

from r800_android_sepolicy_audit import audit, verify_rootfs, MAX_POLICY
from r800_android_rootfs_preflight import snapshot, sha, newc, CAP
from r800_android_init_dependencies import regular
from r800_android_init_rootfs import unique_object
from r800_initramfs_spec import validate_init
from r800_qemu_guest_abi import verify_baseline, read_bounded_json
from r800_qemu_property_kernel import verify_config
from r800_qemu_rootfs_preflight import command, verify_archive
from r800_qemu_system_init import kernel_bytes, observe_boot
from r800_qemu_user_init import EXPECTED, HEARTBEAT_PREFIX

MARKERS = [
    b"r800-stock-policy: load=PASS enforce=1",
    b"r800-stock-policy: current-domain=u:r:kernel:s0",
    b"r800-stock-policy: PASS android-init=not-started relabel=not-tested",
]


def inspect_console(log):
    lines = log.replace(b"\r\n", b"\n").splitlines()
    if [line for line in lines if line.startswith(b"r800-stock-policy:")] != MARKERS:
        raise ValueError("Unexpected stock policy diagnostic sequence")
    startup = EXPECTED.rstrip(b"\n")
    if lines.count(startup) != 1 or lines.index(startup) >= lines.index(MARKERS[0]):
        raise ValueError("Policy diagnostics outside startup window")
    if any(line.startswith(HEARTBEAT_PREFIX) for line in lines[:lines.index(MARKERS[-1])]):
        raise ValueError("Heartbeat before policy diagnostic completion")
    if any(line.startswith((b"r800-property-service:", b"r800-property-client:",
                            b"r800-property-area:", b"r800-policy:")) for line in lines):
        raise ValueError("Unexpected other policy or property diagnostics")
    return {"stock_policy_loaded_reported": True, "enforcing_reported": True,
            "current_domain_reported": "u:r:kernel:s0", "init_domain_entered": False,
            "file_relabel_tested": False, "android_init_started": False,
            "property_service_started": False}


def verify_previous(rootfs, policy, digest, previous_archive):
    if (rootfs.get("status") != "VIRT_ANDROID_ROOTFS_PREFLIGHT_ONLY"
            or rootfs.get("generic_kernel_sha256") != digest
            or rootfs.get("canonical_archive_verified") is not True
            or rootfs.get("ram_mounts_reported") is not True
            or rootfs.get("guest_progress_after_marker_verified") is not True
            or rootfs.get("selinux_policy_loaded") is not False):
        raise ValueError("Successful same-kernel rootfs preflight required")
    archive_sha = verify_rootfs(policy, rootfs)
    if sha(snapshot(previous_archive, CAP)) != archive_sha:
        raise ValueError("Previous rootfs archive identity mismatch")
    return archive_sha


def archive_for(init, compile_evidence, policy):
    info = validate_init(init)
    spec = read_bounded_json(compile_evidence)
    if spec.get("status") != "NON_RELEASE_INITRAMFS_SPEC_ONLY" or spec.get("init") != info:
        raise ValueError("Diagnostic init compile evidence mismatch")
    data = snapshot(init, 2 * 1024 * 1024)
    if sha(data) != info["sha256"]:
        raise ValueError("Diagnostic init changed")
    entries = [(p, (0o040755, b"", 0, 0)) for p in ("dev", "proc", "sys", "data")]
    entries.extend([
        ("dev/console", (0o020600, b"", 5, 1)),
        ("init", (0o100755, data, 0, 0)),
        ("galwear-policy", (0o100400, policy, 0, 0)),
    ])
    return newc(entries), info["sha256"]


def run(a):
    digest = verify_baseline(a.baseline, a.kernel)
    cfg = verify_config(a.config_evidence, digest)
    rootfs = json.loads(snapshot(a.rootfs_report, 262144), object_pairs_hook=unique_object)
    policy = audit(a.product_out, a.checkfc)
    prior_sha = verify_previous(rootfs, policy, digest, a.rootfs_archive)
    blob = snapshot(regular(a.product_out.resolve(strict=True), policy["policy_path"]), MAX_POLICY)
    if sha(blob) != policy["policy_sha256"]:
        raise ValueError("Stock policy changed after audit")
    archive, init_sha = archive_for(a.init, a.compile_evidence, blob)
    raw = kernel_bytes(a.kernel)
    if sha(raw) != digest:
        raise ValueError("Kernel changed after baseline")
    a.out_dir.mkdir(exist_ok=False)
    image, cpio = a.out_dir / "generic-Image", a.out_dir / "stock-policy.cpio"
    image.write_bytes(raw)
    cpio.write_bytes(archive)
    verify_archive(cpio, archive)
    if sha(kernel_bytes(image)) != digest:
        raise ValueError("Kernel staging mismatch")
    log = a.out_dir / "generic-console.log"
    observed = observe_boot(command(image, cpio), log)
    verify_archive(cpio, archive)
    if sha(kernel_bytes(image)) != digest:
        raise ValueError("Kernel changed during boot")
    return {**observed, **inspect_console(log.read_bytes()),
            "status": "VIRT_ANDROID_STOCK_POLICY_LOAD_ONLY",
            "policy_static_audit": policy, "policy_sha256": sha(blob),
            "prior_rootfs_archive_sha256": prior_sha, "archive_sha256": sha(archive),
            "init_sha256": init_sha, "generic_kernel_sha256": digest,
            "config_sha256": cfg["config_sha256"], "expanded_rootfs_booted_in_this_run": False,
            "android_service_permissions_tested": False,
            "exynos9110_emulated": False, "device_contacted": False, "safe_to_flash": False}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ("init", "compile-evidence", "kernel", "baseline", "config-evidence",
                 "rootfs-report", "rootfs-archive", "product-out", "checkfc", "out-dir", "report"):
        p.add_argument("--" + name, type=Path, required=True)
    a = p.parse_args()
    try:
        result = run(a)
        rc = 0
    except (OSError, ValueError, TypeError, KeyError, AttributeError, IndexError,
            EOFError, RuntimeError, subprocess.SubprocessError) as exc:
        result = {"status": "REJECT", "reason": str(exc), "safe_to_flash": False,
                  "android_init_started": False, "property_service_started": False}
        rc = 2
    a.report.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(result["status"])
    return rc

if __name__ == "__main__":
    raise SystemExit(main())
