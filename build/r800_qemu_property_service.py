#!/usr/bin/env python3
"""Boot original libinit property service under the separate GalWear fixture policy."""
import argparse
import json
from pathlib import Path
import subprocess
import tempfile

from r800_android_rootfs_preflight import prepare_entries, newc, snapshot, sha
from r800_android_sepolicy_audit import MAX_POLICY
from r800_android_file_contexts import FILE_CONTEXTS, MAX_CONTEXTS
from r800_android_init_dependencies import regular
from r800_galwear_policy_fixture import audit_fixture, FILE, LABEL, SERVICE, SERVICE_LABEL
from r800_qemu_rootfs_relabel import make_archive, inspect_console as inspect_relabel, PREFIX
from r800_qemu_guest_abi import verify_baseline, read_bounded_json
from r800_qemu_property_kernel import verify_config
from r800_qemu_rootfs_preflight import command, verify_archive
from r800_qemu_system_init import kernel_bytes, observe_boot
from r800_qemu_user_init import HEARTBEAT_PREFIX
from r800_initramfs_spec import validate_init

MARKERS = [
    b"r800-property-service: domain=u:r:init:s0 enforce=1",
    b"r800-property-service: original-libinit socket-created",
    b"r800-property-client: domain=u:r:galwear_property_client:s0 protocol=2",
    b"r800-property-client: socket-set=PASS read=ready",
    b"r800-property-client: socket-update=PASS serial-changed=PASS",
    b"r800-property-client: read-only-rejected=PASS status=0x000b",
    b"r800-property-client: denied-write=PASS status=0x0018 value-unchanged=PASS",
    b"r800-property-service: client-exit=0",
]


def inspect_console(log, paths):
    lines = log.replace(b"\r\n", b"\n").splitlines()
    service = [line for line in lines if line.startswith(
        (b"r800-property-service:", b"r800-property-client:"))]
    if service != MARKERS:
        raise ValueError("Unexpected original libinit/client sequence")
    handover = PREFIX + f"PASS count={len(paths)} service=handover".encode()
    fixture = PREFIX + b"fixture-policy=PASS enforce=1"
    if lines.count(handover) != 1 or lines.count(fixture) != 1 or lines.index(handover) >= lines.index(MARKERS[0]):
        raise ValueError("Missing fixture-policy relabel handover")
    # Reuse the stock relabel parser only for the preceding labeling contract.
    prefix = lines[:lines.index(handover)+1]
    normalized = [line.replace(fixture, PREFIX+b"stock-policy=PASS enforce=1")
                  if line == fixture else line for line in prefix]
    normalized[-1] = handover.replace(b"service=handover", b"service=not-started")
    labels = inspect_relabel(b"\n".join(normalized), paths)["file_labels_reported"]
    if labels.get(FILE) != LABEL or labels.get(SERVICE) != SERVICE_LABEL:
        raise ValueError("Unexpected diagnostic executable labels")
    if any(line.startswith(HEARTBEAT_PREFIX) for line in lines[:lines.index(MARKERS[-1])]):
        raise ValueError("Heartbeat before client completion")
    return {"file_labels_reported": labels, "fixture_policy_loaded_reported": True,
            "enforcing_reported": True, "init_domain_entered": True,
            "property_service_started": True, "client_transition_reported": True,
            "socket_set_update_reported": True, "read_only_status_reported": 0x000B,
            "mac_denied_status_reported": 0x0018, "negative_value_unchanged_reported": True,
            "android_init_started": False, "production_policy": False,
            "stock_policy": False, "safe_to_flash": False}


def verify_prior(report, digest):
    if (report.get("status") != "VIRT_ANDROID_ROOTFS_RELABEL_ONLY"
            or report.get("generic_kernel_sha256") != digest
            or report.get("enforcing_reported") is not True
            or report.get("stock_policy_loaded_reported") is not True
            or report.get("property_service_started") is not False
            or report.get("guest_progress_after_marker_verified") is not True
            or report.get("safe_to_flash") is not False):
        raise ValueError("Matching stock rootfs relabel control required")


def read_contexts(root, policy, checkfc):
    contexts = {}
    with tempfile.TemporaryDirectory(prefix="galwear-service-contexts-") as temp:
        p = Path(temp)/"sepolicy"
        p.write_bytes(policy)
        for index, rel in enumerate(FILE_CONTEXTS):
            src = regular(root, rel)
            if src is None:
                if index == 0:
                    raise ValueError("Platform file_contexts missing")
                continue
            data = snapshot(src, MAX_CONTEXTS)
            data.decode("utf-8")
            if b"\0" in data:
                raise ValueError("Invalid file_contexts")
            f = Path(temp)/str(index)
            f.write_bytes(data)
            subprocess.run([str(checkfc.resolve(strict=True)), str(p), str(f)],
                           check=True, capture_output=True, timeout=30)
            contexts[rel] = data
    return contexts


def run(a):
    digest = verify_baseline(a.baseline, a.kernel)
    cfg = verify_config(a.config_evidence, digest)
    prior = json.loads(snapshot(a.stock_relabel_report, 262144))
    verify_prior(prior, digest)
    root = a.fixture_product_out.resolve(strict=True)
    fixture = audit_fixture(root, a.checkfc, a.analyze)
    if fixture["policy_sha256"] == prior.get("policy_sha256"):
        raise ValueError("Fixture policy must differ from stock control")
    policy = snapshot(regular(root, fixture["policy_path"]), MAX_POLICY)
    if sha(policy) != fixture["policy_sha256"]:
        raise ValueError("Fixture policy changed")
    contexts = read_contexts(root, policy, a.checkfc)
    if sha(contexts[FILE_CONTEXTS[0]]) != fixture["file_contexts_sha256"]:
        raise ValueError("Fixture platform file contexts changed")
    # Reconstruct the stock archive with the same staged executable bytes.
    stock_entries, stock_report = prepare_entries(a.staged, a.stock_product_out,
                                                  a.preflight_init, a.readelf)
    stock_sha = sha(newc(stock_entries))
    if stock_sha != prior.get("prior_rootfs_archive_sha256"):
        raise ValueError("Stock preflight archive identity mismatch")
    entries, report = prepare_entries(a.staged, root, a.preflight_init, a.readelf)
    if report["property_contexts_sha256"] != fixture["property_contexts_sha256"]:
        raise ValueError("Fixture property contexts mismatch")
    # Only partition context files and their parent directories may differ.
    def executable_inventory(r):
        return {p: v for p, v in r["guest_files"].items()
                if "/selinux/" not in p}
    if executable_inventory(report) != executable_inventory(stock_report):
        raise ValueError("Staged binaries changed since stock control")
    init = validate_init(a.init)
    spec = read_bounded_json(a.compile_evidence)
    if spec.get("status") != "NON_RELEASE_INITRAMFS_SPEC_ONLY" or spec.get("init") != init:
        raise ValueError("Service boot compile evidence mismatch")
    binary = snapshot(a.init, 2*1024*1024)
    if sha(binary) != init["sha256"]:
        raise ValueError("Service boot init changed")
    archive, paths = make_archive(entries, binary, policy, contexts)
    raw = kernel_bytes(a.kernel)
    if sha(raw) != digest:
        raise ValueError("Kernel changed")
    a.out_dir.mkdir(exist_ok=False)
    image, cpio = a.out_dir/"generic-Image", a.out_dir/"property-service.cpio"
    image.write_bytes(raw)
    cpio.write_bytes(archive)
    verify_archive(cpio, archive)
    if sha(kernel_bytes(image)) != digest:
        raise ValueError("Kernel staging mismatch")
    log = a.out_dir/"generic-console.log"
    observed = observe_boot(command(image, cpio), log)
    verify_archive(cpio, archive)
    if sha(kernel_bytes(image)) != digest:
        raise ValueError("Kernel changed during boot")
    return {**observed, **inspect_console(log.read_bytes(), paths),
            "status": "VIRT_GALWEAR_ORIGINAL_PROPERTY_SERVICE_ONLY",
            "generic_kernel_sha256": digest, "config_sha256": cfg["config_sha256"],
            "policy_sha256": sha(policy), "stock_policy_sha256": prior["policy_sha256"],
            "prior_rootfs_archive_sha256": stock_sha, "archive_sha256": sha(archive),
            "init_sha256": init["sha256"], "fixture_audit": fixture,
            "file_contexts_sha256": {p: sha(v) for p,v in contexts.items()},
            "exynos9110_emulated": False, "device_contacted": False, "safe_to_flash": False}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ("staged", "stock-product-out", "fixture-product-out", "preflight-init",
                 "init", "compile-evidence", "stock-relabel-report", "kernel",
                 "baseline", "config-evidence", "checkfc", "analyze", "out-dir", "report"):
        p.add_argument("--"+name, type=Path, required=True)
    p.add_argument("--readelf", default="readelf")
    a = p.parse_args()
    try:
        report = run(a)
        rc = 0
    except (OSError, ValueError, TypeError, KeyError, AttributeError, IndexError,
            RuntimeError, subprocess.SubprocessError) as exc:
        report = {"status": "REJECT", "reason": str(exc), "safe_to_flash": False}
        rc = 2
    a.report.write_text(json.dumps(report, indent=2, sort_keys=True)+"\n")
    print(report["status"])
    return rc

if __name__ == "__main__":
    raise SystemExit(main())
