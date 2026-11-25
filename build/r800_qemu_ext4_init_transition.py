#!/usr/bin/env python3
"""Separate EXT4 diagnostic init transition, never boot stock Android init."""
import argparse
import json
from pathlib import Path
import subprocess

import r800_qemu_readonly_disks as disks
from r800_ext4_nosuid_policy_gate import require_ready
from r800_ext4_console_contract import inspect as inspect_stdout
from r800_ext4_exec_access_audit import evaluate_blob as audit_exec_access
import r800_qemu_prelabeled_mounts as labels
from r800_android_rootfs_preflight import snapshot, sha
from r800_android_sepolicy_audit import audit, MAX_POLICY
from r800_android_init_dependencies import regular
from r800_qemu_guest_abi import verify_baseline, read_bounded_json
from r800_qemu_user_init import HEARTBEAT_PREFIX
from r800_initramfs_spec import validate_init

TARGET = "system/bin/init"
PREFIX = b"r800-ext4-transition: "
MARKERS = [
    PREFIX+b"exec=/system/bin/init diagnostic-only",
    PREFIX+b"domain=u:r:init:s0 enforce=1 pid=1",
    PREFIX+b"executable=/system/bin/init label=u:object_r:init_exec:s0",
    PREFIX+b"PASS diagnostic-only stock-init=not-started",
]


def verify_substitution(old, new, diagnostic_sha):
    for field in ("policy_sha256", "platform_file_contexts_sha256",
                  "property_contexts_sha256", "image_bytes"):
        if old[field] != new[field]:
            raise ValueError("Transition image metadata changed: "+field)
    orig, changed = old["verified_system_entries"], new["verified_system_entries"]
    if TARGET not in orig or TARGET not in changed or set(orig) != set(changed):
        raise ValueError("Canonical system inode inventory changed")
    expected = dict(orig)
    expected[TARGET] = {**orig[TARGET], "sha256": diagnostic_sha}
    if changed != expected or orig[TARGET]["context"] != "u:object_r:init_exec:s0":
        raise ValueError("Unexpected system inode change")
    if (orig[TARGET]["sha256"] == diagnostic_sha or old["image_sha256"] == new["image_sha256"]
            or new.get("diagnostic_init_substitution") != {
                "path":"/"+TARGET,"original_sha256":orig[TARGET]["sha256"],
                "diagnostic_sha256":diagnostic_sha}):
        raise ValueError("Diagnostic substitution identity mismatch")


def verify_prior(prior, kernel, config, policy, old_records, plan):
    if (prior.get("status") != "VIRT_ANDROID_PRELABELED_MOUNTS_ONLY"
            or prior.get("generic_kernel_sha256") != kernel
            or prior.get("config_sha256") != config
            or prior.get("policy_sha256") != policy
            or prior.get("disk_hashes_unchanged") is not True
            or prior.get("guest_selinux_labels_verified") is not True
            or prior.get("enforcing_reported") is not True
            or prior.get("current_domain_reported") != "u:r:kernel:s0"
            or prior.get("mount_noexec_requested") is not True
            or prior.get("guest_progress_after_marker_verified") is not True
            or prior.get("android_init_started") is not False
            or prior.get("safe_to_flash") is not False
            or prior.get("effective_labels_reported") != plan
            or labels.identity(prior["disks"]) != labels.identity(old_records)):
        raise ValueError("Matching original labeled mount control required")


def inspect_console(log, records, plan):
    evidence = labels.inspect_console(log, records, plan)
    lines = log.replace(b"\r\n",b"\n").splitlines()
    if [x for x in lines if x.startswith(PREFIX)] != MARKERS:
        raise ValueError("Unexpected EXT4 init transition sequence")
    exec_modes = [b"r800-ext4-exec: "+d["name"].encode()+b" noexec="+
                  (b"0" if d["name"]=="system" else b"1") for d in records]
    if [x for x in lines if x.startswith(b"r800-ext4-exec:")] != exec_modes:
        raise ValueError("Unexpected partition execution flags")
    mount_end = disks.PREFIX+f"PASS count={len(records)} policy=not-loaded android=not-started".encode()
    label_end = labels.PREFIX+f"PASS count={len(plan)} android=not-started".encode()
    if not (lines.index(exec_modes[-1]) < lines.index(mount_end) <
            lines.index(label_end) < lines.index(MARKERS[0])):
        raise ValueError("EXT4 handover out of order")
    if any(x.startswith(HEARTBEAT_PREFIX) for x in lines[:lines.index(MARKERS[-1])]):
        raise ValueError("Heartbeat before diagnostic transition")
    stdout = inspect_stdout(log, ("kernel","init"),
        (disks.EXPECTED.rstrip(b"\n"), MARKERS[0]),
        (exec_modes[0], MARKERS[1]))
    return {**evidence, **stdout, "current_domain_reported":"u:r:init:s0",
            "initial_domain_reported":"u:r:kernel:s0","init_domain_entered":True,
            "mount_noexec_requested":False,"only_system_exec_reported":True,
            "diagnostic_pid1_only":True,"original_init_executed":False}


def run(a):
    kernel = verify_baseline(a.baseline,a.kernel)
    config = read_bounded_json(a.config_evidence)
    old_args = argparse.Namespace(**vars(a))
    old_args.system_report, old_args.system_dir = a.original_system_report,a.original_system_dir
    policy, old_records = disks.inventory(old_args)
    new_policy, records = disks.inventory(a,transition=True)
    if policy != new_policy or labels.identity(old_records[1:]) != labels.identity(records[1:]):
        raise ValueError("Non-system disk identities changed")
    old = disks.report(a.original_system_report,"ANDROID_SYSTEM_EXT4_LABELED_STATIC_ONLY")
    new = disks.report(a.system_report,"ANDROID_SYSTEM_EXT4_TRANSITION_STATIC_ONLY")
    info = validate_init(a.diagnostic_init)
    spec = read_bounded_json(a.diagnostic_compile_evidence)
    if spec.get("status") != "NON_RELEASE_INITRAMFS_SPEC_ONLY" or spec.get("init") != info:
        raise ValueError("Diagnostic compile evidence mismatch")
    verify_substitution(old,new,info["sha256"])
    extra = disks.report(a.context_report,"ANDROID_CONTEXT_PARTITIONS_STATIC_ONLY")
    runtime = disks.report(a.runtime_report,"ANDROID_RUNTIME_APEX_PAYLOAD_PRESERVED_ONLY")
    plan = labels.label_plan(new,extra,runtime)
    if plan != labels.label_plan(old,extra,runtime):
        raise ValueError("Label inventory changed")
    prior = disks.report(a.label_report,"VIRT_ANDROID_PRELABELED_MOUNTS_ONLY")
    verify_prior(prior,kernel,config["config_sha256"],policy,old_records,plan)
    root = a.product_out.resolve(strict=True)
    audited = audit(root,a.checkfc)
    blob = snapshot(regular(root,audited["policy_path"]),MAX_POLICY)
    if audited["policy_sha256"] != policy or sha(blob) != policy:
        raise ValueError("Policy identity mismatch")
    nosuid = require_ready(blob, "stock", a.seinfo, a.sesearch)
    access = audit_exec_access(blob,new,extra,runtime,"stock",a.sesearch)
    manifest = "".join(p+" "+v+"\n" for p,v in plan.items()).encode("ascii")
    if len(manifest)>256*1024:
        raise ValueError("Label manifest exceeds bounds")
    result = disks.run(a,expected_inventory=(policy,records),transition=True,
        extra_entries=[("galwear-policy",(0o100400,blob,0,0)),
                       ("galwear-labels.list",(0o100400,manifest,0,0))],
        label_parser=lambda log,actual:inspect_console(log,actual,plan))
    return {**result,"nosuid_policy_prerequisites":nosuid,"exec_access_advisory":access,"original_system_sha256":old["image_sha256"],
            "diagnostic_system_sha256":new["image_sha256"],
            "diagnostic_init_sha256":info["sha256"],"label_manifest_sha256":sha(manifest),
            "prior_label_archive_sha256":prior["archive_sha256"],
            "android_init_started":False,"property_service_started":False,"safe_to_flash":False}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ("system-dir","system-report","original-system-dir","original-system-report",
                 "context-dir","context-report","runtime-dir","runtime-report","kernel","baseline",
                 "config-evidence","init","compile-evidence","diagnostic-init",
                 "diagnostic-compile-evidence","product-out","checkfc","label-report","out-dir","report"):
        p.add_argument("--"+name,type=Path,required=True)
    p.add_argument("--seinfo",default="seinfo")
    p.add_argument("--sesearch",default="sesearch")
    a=p.parse_args()
    try:
        result=run(a)
        rc=0
    except (OSError,ValueError,TypeError,KeyError,AttributeError,RuntimeError,subprocess.SubprocessError) as exc:
        result={"status":"REJECT","reason":str(exc),"safe_to_flash":False}
        rc=2
    a.report.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
    print(result["status"])
    return rc

if __name__=="__main__":
    raise SystemExit(main())
