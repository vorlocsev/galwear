#!/usr/bin/env python3
"""Audit a locally source-built Android 11 precompiled policy, never load it.

Mirrors the precompiled policy selection and partition ID comparisons from
pinned AOSP init/selinux.cpp. No claim of provenance or kernel acceptance.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import tempfile

from r800_android_rootfs_preflight import CONTEXTS, snapshot
from r800_android_init_dependencies import regular
from r800_android_init_rootfs import unique_object

MAX_POLICY = 16 * 1024 * 1024
POLICY_PATHS = ("odm/etc/selinux/precompiled_sepolicy",
                "vendor/etc/selinux/precompiled_sepolicy")
PARTITIONS = (("system", "plat"), ("system_ext", "system_ext"), ("product", "product"))
HASH = re.compile(r"[a-f0-9]{64}")


def sha(blob):
    return hashlib.sha256(blob).hexdigest()


def header(blob):
    if len(blob) < 32:
        raise ValueError("Truncated SELinux policy header")
    magic, length = struct.unpack_from("<II", blob)
    if magic != 0xf97cff8c or length != 8 or blob[8:16] != b"SE Linux":
        raise ValueError("Unexpected SELinux policy magic or identifier")
    version, config, symbols, contexts = struct.unpack_from("<IIII", blob, 16)
    if not 19 <= version <= 31:
        raise ValueError("Policy version outside pinned kernel MLS range 19..31")
    if not config & 1:
        raise ValueError("Android MLS policy required")
    if not symbols or not contexts:
        raise ValueError("Empty policy tables")
    return {"policy_version": version, "mls_enabled": True, "config_bits": config,
            "symbol_tables": symbols, "object_context_tables": contexts}


def partition_id(root, rel):
    raw = snapshot(regular(root, rel), 256)
    text = raw.decode("ascii").strip()
    if not HASH.fullmatch(text):
        raise ValueError("Invalid partition policy identifier: " + rel)
    return text


def audit(product, checkfc):
    product = product.resolve(strict=True)
    if checkfc.is_symlink() or not checkfc.is_file():
        raise ValueError("Explicit AOSP host checkfc executable required")
    tool = checkfc.resolve(strict=True)
    tool_hash = sha(snapshot(tool, MAX_POLICY))
    # AOSP chooses ODM first if present; do not silently fall back on mismatch.
    rel = next((p for p in POLICY_PATHS if regular(product, p) is not None), None)
    if rel is None:
        raise ValueError("Precompiled Android sepolicy missing")
    blob = snapshot(regular(product, rel), MAX_POLICY)
    info = header(blob)
    ids = {}
    for partition, stem in PARTITIONS:
        suffix = stem + "_sepolicy_and_mapping.sha256"
        actual = partition_id(product, partition + "/etc/selinux/" + suffix)
        expected = partition_id(product, rel + "." + suffix)
        if actual != expected:
            raise ValueError("Precompiled partition policy ID mismatch: " + partition)
        ids[partition] = actual
    context_hashes = {}
    with tempfile.TemporaryDirectory(prefix="galwear-checkfc-") as temp:
        root = Path(temp)
        policy = root / "sepolicy"
        policy.write_bytes(blob)
        for index, path in enumerate(CONTEXTS):
            source = regular(product, path)
            if source is None:
                if index == 0:
                    raise ValueError("Platform property contexts missing")
                continue
            data = snapshot(source, 1024 * 1024)
            data.decode("utf-8")
            if b"\0" in data:
                raise ValueError("Invalid property context text")
            contexts = root / ("contexts-" + str(index))
            contexts.write_bytes(data)
            subprocess.run([str(tool), "-p", str(policy), str(contexts)],
                           capture_output=True, text=True, check=True, timeout=30)
            context_hashes[path] = sha(data)
        if sha(policy.read_bytes()) != sha(blob):
            raise ValueError("Policy changed during checkfc")
    if sha(snapshot(tool, MAX_POLICY)) != tool_hash:
        raise ValueError("checkfc changed during audit")
    return {
        "status": "ANDROID_SEPOLICY_STATIC_COMPATIBILITY_ONLY",
        "policy_path": rel, "policy_sha256": sha(blob), "policy_bytes": len(blob),
        **info, "pinned_kernel_policy_version_max": 31,
        "partition_policy_ids": ids, "partition_ids_matched": True,
        "property_contexts_sha256": context_hashes,
        "checkfc_sha256": tool_hash, "checkfc_property_contexts_passed": True,
        "policy_source_authenticity_verified": False,
        "policy_loaded": False, "kernel_policy_compatibility_tested": False,
        "android_init_started": False, "property_service_started": False,
        "safe_to_flash": False,
    }


def verify_rootfs(policy, rootfs):
    if (rootfs.get("status") not in ("ANDROID_ROOTFS_PREFLIGHT_ARCHIVE_ONLY", "VIRT_ANDROID_ROOTFS_PREFLIGHT_ONLY")
            or rootfs.get("safe_to_flash") is not False
            or rootfs.get("property_contexts_sha256") != policy["property_contexts_sha256"]):
        raise ValueError("Rootfs property context identity mismatch")
    digest = rootfs.get("archive_sha256", "")
    if not isinstance(digest, str) or not HASH.fullmatch(digest):
        raise ValueError("Missing rootfs archive identity")
    return digest


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--product-out", required=True, type=Path)
    p.add_argument("--checkfc", required=True, type=Path)
    p.add_argument("--report", required=True, type=Path)
    p.add_argument("--rootfs-report", type=Path)
    a = p.parse_args()
    try:
        report = audit(a.product_out, a.checkfc)
        report["rootfs_context_identity_matched"] = False
        if a.rootfs_report:
            rootfs = json.loads(snapshot(a.rootfs_report, 262144), object_pairs_hook=unique_object)
            report["rootfs_archive_sha256"] = verify_rootfs(report, rootfs)
            report["rootfs_context_identity_matched"] = True
        rc = 0
    except (OSError, ValueError, KeyError, TypeError, AttributeError, RuntimeError, subprocess.SubprocessError) as exc:
        report = {"status": "REJECT", "reason": str(exc), "safe_to_flash": False}
        rc = 2
    a.report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(report["status"])
    return rc

if __name__ == "__main__":
    raise SystemExit(main())
