#!/usr/bin/env python3
"""Expanded rootfs stock-policy relabel gate. Never execute Android binaries."""
import argparse
import json
from pathlib import Path
import re
import subprocess

from r800_android_rootfs_preflight import prepare_entries, newc, snapshot, sha
from r800_android_sepolicy_audit import audit, MAX_POLICY
from r800_android_file_contexts import FILE_CONTEXTS, MAX_CONTEXTS
from r800_android_init_dependencies import regular
from r800_qemu_android_stock_policy import verify_previous
from r800_qemu_guest_abi import verify_baseline, read_bounded_json
from r800_qemu_property_kernel import verify_config
from r800_qemu_rootfs_preflight import command, verify_archive
from r800_qemu_system_init import kernel_bytes, observe_boot
from r800_qemu_user_init import EXPECTED, HEARTBEAT_PREFIX
from r800_initramfs_spec import validate_init

PREFIX = b"r800-relabel: "
START = PREFIX + b"stock-policy=PASS enforce=1"
CONTEXT = re.compile(rb"u:object_r:[A-Za-z0-9_]+:s0(?::[A-Za-z0-9_,.:-]+)?")

def make_archive(entries, binary, policy, contexts):
    table = dict(entries)
    table["init"] = (0o100755, binary, 0, 0)
    for name, blob in {"galwear-policy": policy, **contexts}.items():
        if name in table:
            raise ValueError("Unexpected existing policy path")
        table[name] = (0o100400 if name == "galwear-policy" else 0o100644, blob, 0, 0)
        for parent in Path(name).parents:
            if str(parent) != ".":
                table.setdefault(str(parent), (0o040755, b"", 0, 0))
    paths = ["/"+name for name in table if name.split("/")[0] in (
        "system", "system_ext", "vendor", "product", "odm", "apex", "linkerconfig")]
    paths += ["/dev/socket"]
    paths = sorted(paths, key=lambda p: (p.count("/"), p))
    if not 1 <= len(paths) <= 512:
        raise ValueError("Relabel count outside bounds")
    manifest = ("\n".join(paths)+"\n").encode("ascii")
    if len(manifest) > 65536:
        raise ValueError("Relabel manifest exceeds bounds")
    table["galwear-relabel.list"] = (0o100400, manifest, 0, 0)
    ordered = sorted(table.items(), key=lambda item: (item[1][0] & 0o170000 != 0o040000,
                                                      item[0].count("/"), item[0]))
    return newc(ordered), paths

def inspect_console(log, paths):
    lines = log.replace(b"\r\n", b"\n").splitlines()
    observed = [line for line in lines if line.startswith(PREFIX)]
    end = PREFIX + f"PASS count={len(paths)} service=not-started".encode()
    if len(observed) != len(paths)+2 or observed[0] != START or observed[-1] != end:
        raise ValueError("Incomplete relabel diagnostics")
    start = EXPECTED.rstrip(b"\n")
    if lines.count(start) != 1 or lines.index(start) >= lines.index(START):
        raise ValueError("Relabel outside startup window")
    if any(line.startswith(HEARTBEAT_PREFIX) for line in lines[:lines.index(end)]):
        raise ValueError("Heartbeat before relabel completion")
    labels = {}
    for path, line in zip(paths, observed[1:-1]):
        prefix = PREFIX+b"path="+path.encode("ascii")+b" context="
        if not line.startswith(prefix) or not CONTEXT.fullmatch(line[len(prefix):]):
            raise ValueError("Unexpected path or context in relabel diagnostics")
        labels[path] = line[len(prefix):].decode("ascii")
    if any(line.startswith((b"r800-property-service:", b"r800-property-client:")) for line in lines):
        raise ValueError("Unexpected service diagnostics")
    return {"file_labels_reported": labels, "relabel_count": len(labels),
            "stock_policy_loaded_reported": True, "enforcing_reported": True,
            "android_init_started": False, "property_service_started": False,
            "service_permissions_tested": False}

def run(a):
    digest = verify_baseline(a.baseline, a.kernel)
    cfg = verify_config(a.config_evidence, digest)
    rootfs = json.loads(snapshot(a.rootfs_report, 262144))
    stock = json.loads(snapshot(a.stock_policy_report, 262144))
    transition = json.loads(snapshot(a.transition_report, 262144))
    policy = audit(a.product_out, a.checkfc)
    prior = verify_previous(rootfs, policy, digest, a.rootfs_archive)
    if (stock.get("status") != "VIRT_ANDROID_STOCK_POLICY_LOAD_ONLY"
            or stock.get("prior_rootfs_archive_sha256") != prior
            or stock.get("generic_kernel_sha256") != digest
            or stock.get("policy_sha256") != policy["policy_sha256"]
            or stock.get("stock_policy_loaded_reported") is not True
            or stock.get("enforcing_reported") is not True
            or stock.get("safe_to_flash") is not False):
        raise ValueError("Matching stock policy run required")
    if (transition.get("status") != "VIRT_ANDROID_DIAGNOSTIC_INIT_DOMAIN_ONLY"
            or transition.get("generic_kernel_sha256") != digest
            or transition.get("policy_sha256") != policy["policy_sha256"]
            or transition.get("init_domain_entered") is not True
            or transition.get("restorecon_reported") is not True
            or transition.get("enforcing_reported") is not True
            or transition.get("safe_to_flash") is not False):
        raise ValueError("Matching diagnostic transition required")
    context_audit = transition["file_contexts_audit"]
    if (context_audit.get("checkfc_file_contexts_passed") is not True
            or context_audit.get("policy_sha256") != policy["policy_sha256"]):
        raise ValueError("File contexts audit mismatch")
    hashes = context_audit["file_contexts_sha256"]
    if FILE_CONTEXTS[0] not in hashes or not set(hashes) <= set(FILE_CONTEXTS):
        raise ValueError("Unexpected file contexts inventory")
    root = a.product_out.resolve(strict=True)
    contexts = {}
    for rel, expected in hashes.items():
        blob = snapshot(regular(root, rel), MAX_CONTEXTS)
        if sha(blob) != expected:
            raise ValueError("File contexts changed: "+rel)
        contexts[rel] = blob
    blob = snapshot(regular(root, policy["policy_path"]), MAX_POLICY)
    if sha(blob) != policy["policy_sha256"]:
        raise ValueError("Stock policy changed")
    entries, base = prepare_entries(a.staged, a.product_out, a.preflight_init, a.readelf)
    if sha(newc(entries)) != prior or base["property_contexts_sha256"] != policy["property_contexts_sha256"]:
        raise ValueError("Canonical preflight archive changed")
    init = validate_init(a.init)
    spec = read_bounded_json(a.compile_evidence)
    if spec.get("status") != "NON_RELEASE_INITRAMFS_SPEC_ONLY" or spec.get("init") != init:
        raise ValueError("Relabel init compile evidence mismatch")
    binary = snapshot(a.init, 2*1024*1024)
    if sha(binary) != init["sha256"]:
        raise ValueError("Relabel init changed")
    archive, paths = make_archive(entries, binary, blob, contexts)
    raw = kernel_bytes(a.kernel)
    if sha(raw) != digest:
        raise ValueError("Kernel changed")
    a.out_dir.mkdir(exist_ok=False)
    image, cpio = a.out_dir/"generic-Image", a.out_dir/"relabel.cpio"
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
            "status": "VIRT_ANDROID_ROOTFS_RELABEL_ONLY",
            "generic_kernel_sha256": digest, "config_sha256": cfg["config_sha256"],
            "prior_rootfs_archive_sha256": prior, "archive_sha256": sha(archive),
            "policy_sha256": sha(blob), "file_contexts_sha256": hashes,
            "init_sha256": init["sha256"], "exynos9110_emulated": False,
            "device_contacted": False, "safe_to_flash": False}

def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ("staged", "product-out", "preflight-init", "init", "compile-evidence",
                 "rootfs-report", "rootfs-archive", "stock-policy-report", "transition-report",
                 "kernel", "baseline", "config-evidence", "checkfc", "out-dir", "report"):
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
