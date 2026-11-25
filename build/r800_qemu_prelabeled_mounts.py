#!/usr/bin/env python3
"""Check effective SELinux labels of pre-labeled Android disks in generic virt.

No restorecon, setxattr, exec, policy relaxation or real APEX activation.
"""
import argparse
import json
from pathlib import Path
import re
import subprocess

import r800_qemu_readonly_disks as disks
from r800_android_rootfs_preflight import snapshot, sha
from r800_android_sepolicy_audit import audit, MAX_POLICY
from r800_android_init_dependencies import regular
from r800_android_system_ext4 import LABEL
from r800_android_runtime_extract import FILES
from r800_qemu_guest_abi import verify_baseline, read_bounded_json
from r800_qemu_user_init import HEARTBEAT_PREFIX

PREFIX = b"r800-disk-label: "
START = PREFIX + b"policy=PASS domain=u:r:kernel:s0 enforce=1"
PATH = re.compile(r"/[A-Za-z0-9_.+/-]+")


def label_plan(system, extra, runtime):
    result = {}

    def add(path, label, root):
        if (not isinstance(path, str) or not PATH.fullmatch(path)
                or str(Path(path)) != path or ".." in Path(path).parts
                or not (path == root or path.startswith(root+"/"))
                or len(path.encode("ascii")) > 511 or not isinstance(label,str)
                or not LABEL.fullmatch(label) or len(label) > 255 or path in result):
            raise ValueError("Invalid or duplicate audited label path: "+str(path))
        result[path] = label

    def partition(name, entries):
        if name not in entries:
            raise ValueError("Partition root missing: "+name)
        for path, info in entries.items():
            add("/"+path, info["context"], "/"+name)

    partition("system", system["verified_system_entries"])
    for name, info in extra["partitions"].items():
        if name not in disks.ORDER[1:-1]:
            raise ValueError("Unexpected label partition")
        partition(name, info["entries"])
    apex = "/apex/com.android.runtime"
    expected = {"/","/bin","/lib64","/lib64/bionic"} | {"/"+f for f in FILES}
    if set(runtime["selected_inode_labels"]) != expected:
        raise ValueError("Incomplete runtime label inventory")
    for path, info in runtime["selected_inode_labels"].items():
        add(apex+("" if path=="/" else path), info["context"], apex)
    required = {"/system", "/system/bin/galwear_property_service",
                "/system/bin/galwear_property_client",
                "/system/etc/selinux/plat_property_contexts"}
    if not required <= set(result):
        raise ValueError("Incomplete system label inventory")
    if not any(result.get(p) == "u:object_r:init_exec:s0" for p in
               ("/system/bin/init","/system/bin/bootstrap/init")):
        raise ValueError("Original init executable label missing")
    if not 1 <= len(result) <= 1024:
        raise ValueError("Label inventory outside bounds")
    return dict(sorted(result.items()))


def identity(records):
    return [{k:d[k] for k in ("name","sha256","bytes","manifest_slot")} for d in records]


def verify_previous(prior, kernel, config, policy, records):
    if (prior.get("status") != "VIRT_ANDROID_READONLY_BLOCK_MOUNTS_ONLY"
            or prior.get("generic_kernel_sha256") != kernel
            or prior.get("config_sha256") != config
            or prior.get("policy_sha256") != policy
            or prior.get("safe_to_flash") is not False
            or prior.get("disk_hashes_unchanged") is not True
            or prior.get("block_read_only_reported") is not True
            or prior.get("ext4_read_only_reported") is not True
            or prior.get("disk_serials_verified") is not True
            or prior.get("guest_progress_after_marker_verified") is not True
            or prior.get("selinux_policy_loaded") is not False
            or prior.get("mounted_disk_count") != len(records)
            or identity(prior["disks"]) != identity(records)):
        raise ValueError("Matching successful no-policy readonly mount control required")


def inspect_console(log, records, labels):
    lines = log.replace(b"\r\n",b"\n").splitlines()
    end = PREFIX+f"PASS count={len(labels)} android=not-started".encode()
    expected = [START]+[PREFIX+b"path="+p.encode()+b" context="+v.encode()
                        for p,v in labels.items()]+[end]
    if [line for line in lines if line.startswith(PREFIX)] != expected:
        raise ValueError("Unexpected effective label diagnostics")
    mount_end = disks.PREFIX+f"PASS count={len(records)} policy=not-loaded android=not-started".encode()
    if lines.count(mount_end) != 1 or lines.index(mount_end) >= lines.index(START):
        raise ValueError("Policy loaded before readonly mount completion")
    if any(line.startswith(HEARTBEAT_PREFIX) for line in lines[:lines.index(end)]):
        raise ValueError("Heartbeat before effective label checks")
    return {"selinux_policy_loaded":True,"guest_selinux_labels_verified":True,
            "enforcing_reported":True,"current_domain_reported":"u:r:kernel:s0",
            "checked_label_count":len(labels),"effective_labels_reported":labels,
            "android_mount_paths_used":True,"mount_noexec_requested":True,
            "file_relabel_tested":False,"android_init_started":False,
            "apex_activation_tested":False,"property_service_started":False}


def run(a):
    kernel = verify_baseline(a.baseline,a.kernel)
    config = read_bounded_json(a.config_evidence)
    policy_sha, records = disks.inventory(a)
    prior = disks.report(a.mount_report,"VIRT_ANDROID_READONLY_BLOCK_MOUNTS_ONLY")
    verify_previous(prior,kernel,config["config_sha256"],policy_sha,records)
    root = a.product_out.resolve(strict=True)
    policy = audit(root,a.checkfc)
    if policy["policy_sha256"] != policy_sha:
        raise ValueError("Policy does not match disk reports")
    blob = snapshot(regular(root,policy["policy_path"]),MAX_POLICY)
    if sha(blob) != policy_sha:
        raise ValueError("Policy changed")
    system = disks.report(a.system_report,"ANDROID_SYSTEM_EXT4_LABELED_STATIC_ONLY")
    extra = disks.report(a.context_report,"ANDROID_CONTEXT_PARTITIONS_STATIC_ONLY")
    runtime = disks.report(a.runtime_report,"ANDROID_RUNTIME_APEX_PAYLOAD_PRESERVED_ONLY")
    if any(r["policy_sha256"] != policy_sha for r in (system,extra,runtime)):
        raise ValueError("Label report policy changed")
    labels = label_plan(system,extra,runtime)
    manifest = "".join(p+" "+v+"\n" for p,v in labels.items()).encode("ascii")
    if len(manifest)>256*1024:
        raise ValueError("Label manifest exceeds bounds")
    result = disks.run(a,expected_inventory=(policy_sha,records),
        extra_entries=[("galwear-policy",(0o100400,blob,0,0)),
                       ("galwear-labels.list",(0o100400,manifest,0,0))],
        label_parser=lambda log,actual:inspect_console(log,actual,labels))
    return {**result,"label_manifest_sha256":sha(manifest),
            "prior_mount_archive_sha256":prior["archive_sha256"],
            "stock_policy_source_authenticity_verified":False,
            "all_partition_inodes_audited":False}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ("system-dir","system-report","context-dir","context-report","runtime-dir","runtime-report",
                 "kernel","baseline","config-evidence","init","compile-evidence","out-dir","report",
                 "product-out","checkfc","mount-report"):
        p.add_argument("--"+name,type=Path,required=True)
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
