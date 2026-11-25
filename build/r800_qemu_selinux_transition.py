#!/usr/bin/env python3
"""Run a stock-policy restorecon/exec transition probe on disposable virt only."""
import argparse
import json
from pathlib import Path
import subprocess

from r800_android_file_contexts import audit_files, MAX_CONTEXTS
from r800_android_sepolicy_audit import audit, MAX_POLICY
from r800_android_rootfs_preflight import snapshot, sha, newc
from r800_android_init_dependencies import regular
from r800_initramfs_spec import validate_init
from r800_qemu_guest_abi import verify_baseline, read_bounded_json
from r800_qemu_property_kernel import verify_config
from r800_qemu_rootfs_preflight import command, verify_archive
from r800_qemu_system_init import kernel_bytes, observe_boot
from r800_qemu_user_init import EXPECTED, HEARTBEAT_PREFIX

MARKERS = [
    b"r800-transition: stock-policy=PASS domain=u:r:kernel:s0",
    b"r800-transition: restorecon=PASS label=u:object_r:init_exec:s0",
    b"r800-transition: domain=u:r:init:s0 enforce=1",
    b"r800-transition: PASS diagnostic-only stock-init=not-started",
]


def inspect_console(log):
    lines = log.replace(b"\r\n", b"\n").splitlines()
    if [line for line in lines if line.startswith(b"r800-transition:")] != MARKERS:
        raise ValueError("Unexpected SELinux transition diagnostic sequence")
    startup = EXPECTED.rstrip(b"\n")
    if lines.count(startup) != 1 or lines.index(startup) >= lines.index(MARKERS[0]):
        raise ValueError("Transition outside startup window")
    if any(line.startswith(HEARTBEAT_PREFIX) for line in lines[:lines.index(MARKERS[-1])]):
        raise ValueError("Heartbeat before SELinux transition")
    if any(line.startswith((b"r800-property-service:", b"r800-property-client:")) for line in lines):
        raise ValueError("Unexpected property service diagnostics")
    return {"restorecon_reported": True, "init_exec_label_reported": True,
            "init_domain_entered": True, "enforcing_reported": True,
            "diagnostic_executable_only": True, "android_init_started": False,
            "property_service_started": False}


def make_archive(init, compile_report, policy, contexts):
    info = validate_init(init)
    evidence = read_bounded_json(compile_report)
    if evidence.get("status") != "NON_RELEASE_INITRAMFS_SPEC_ONLY" or evidence.get("init") != info:
        raise ValueError("Diagnostic compile evidence mismatch")
    binary = snapshot(init, 2 * 1024 * 1024)
    if sha(binary) != info["sha256"]:
        raise ValueError("Diagnostic executable changed")
    dirs = {"dev", "proc", "sys", "data", "system", "system/bin"}
    for rel in contexts:
        dirs.update(str(p) for p in Path(rel).parents if str(p) != ".")
    entries = [(p, (0o040755, b"", 0, 0)) for p in sorted(dirs, key=lambda p: (p.count("/"), p))]
    entries += [("dev/console", (0o020600, b"", 5, 1)),
                ("init", (0o100755, binary, 0, 0)),
                ("system/bin/init", (0o100755, binary, 0, 0)),
                ("galwear-policy", (0o100400, policy, 0, 0))]
    entries += [(rel, (0o100644, blob, 0, 0)) for rel, blob in sorted(contexts.items())]
    return newc(entries), info["sha256"]


def run(a):
    digest = verify_baseline(a.baseline, a.kernel)
    cfg = verify_config(a.config_evidence, digest)
    previous = json.loads(snapshot(a.stock_policy_report, 262144))
    if previous.get("generic_kernel_sha256") != digest:
        raise ValueError("Stock policy run used different kernel")
    contexts_report = audit_files(a.product_out, a.checkfc, previous)
    policy = audit(a.product_out, a.checkfc)
    if policy["policy_sha256"] != contexts_report["policy_sha256"]:
        raise ValueError("Policy audit identity mismatch")
    root = a.product_out.resolve(strict=True)
    blob = snapshot(regular(root, policy["policy_path"]), MAX_POLICY)
    if sha(blob) != policy["policy_sha256"]:
        raise ValueError("Stock policy changed")
    contexts = {}
    for rel, expected in contexts_report["file_contexts_sha256"].items():
        data = snapshot(regular(root, rel), MAX_CONTEXTS)
        if sha(data) != expected:
            raise ValueError("File contexts changed: " + rel)
        contexts[rel] = data
    archive, init_sha = make_archive(a.init, a.compile_evidence, blob, contexts)
    raw = kernel_bytes(a.kernel)
    if sha(raw) != digest:
        raise ValueError("Kernel changed")
    a.out_dir.mkdir(exist_ok=False)
    image, cpio = a.out_dir / "generic-Image", a.out_dir / "transition.cpio"
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
            "status": "VIRT_ANDROID_DIAGNOSTIC_INIT_DOMAIN_ONLY",
            "generic_kernel_sha256": digest, "config_sha256": cfg["config_sha256"],
            "archive_sha256": sha(archive), "init_sha256": init_sha,
            "policy_sha256": sha(blob), "file_contexts_audit": contexts_report,
            "expanded_rootfs_booted_in_this_run": False,
            "exynos9110_emulated": False, "device_contacted": False,
            "safe_to_flash": False}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ("init", "compile-evidence", "kernel", "baseline", "config-evidence",
                 "stock-policy-report", "product-out", "checkfc", "out-dir", "report"):
        p.add_argument("--" + name, type=Path, required=True)
    a = p.parse_args()
    try:
        report = run(a)
        rc = 0
    except (OSError, ValueError, TypeError, KeyError, AttributeError, IndexError,
            EOFError, RuntimeError, subprocess.SubprocessError) as exc:
        report = {"status": "REJECT", "reason": str(exc), "safe_to_flash": False,
                  "android_init_started": False, "property_service_started": False}
        rc = 2
    a.report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(report["status"])
    return rc

if __name__ == "__main__":
    raise SystemExit(main())
