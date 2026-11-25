#!/usr/bin/env python3
"""Original libinit property-service fixture on pre-labeled readonly EXT4."""
import argparse
import json
from pathlib import Path
import subprocess

import r800_qemu_readonly_disks as disks
from r800_ext4_nosuid_policy_gate import require_ready
from r800_ext4_console_contract import inspect as inspect_stdout
from r800_ext4_linker_resolution import evaluate as audit_linker_resolution
from r800_ext4_elf_abi import evaluate as audit_elf_abi
from r800_aosp_artifact_origin import bind_system, STATUS as ORIGIN_STATUS
from r800_ext4_exec_access_audit import evaluate_blob as audit_exec_access
import r800_qemu_prelabeled_mounts as labels
from r800_qemu_property_service import MARKERS
from r800_galwear_policy_fixture import audit_fixture, FILE, LABEL, SERVICE, SERVICE_LABEL
from r800_android_init_rootfs import CONFIG
from r800_android_rootfs_preflight import snapshot, sha
from r800_android_sepolicy_audit import MAX_POLICY
from r800_android_init_dependencies import regular
from r800_qemu_guest_abi import verify_baseline, read_bounded_json
from r800_qemu_user_init import HEARTBEAT_PREFIX

START = labels.PREFIX+b"fixture-policy=PASS domain=u:r:kernel:s0 enforce=1"
RAM = b"r800-ext4-service: ram-dev-data=PASS"
EXEC = b"r800-ext4-service: exec=libinit-harness"


def verify_prior(prior, kernel, config, stock, runtime):
    if (prior.get("status") != "VIRT_ANDROID_EXT4_DIAGNOSTIC_INIT_DOMAIN_ONLY"
            or prior.get("generic_kernel_sha256") != kernel
            or prior.get("config_sha256") != config
            or prior.get("policy_sha256") != stock["policy_sha256"]
            or prior.get("original_system_sha256") != stock["image_sha256"]
            or prior.get("init_domain_entered") is not True
            or prior.get("diagnostic_pid1_only") is not True
            or prior.get("enforcing_reported") is not True
            or prior.get("disk_hashes_unchanged") is not True
            or prior.get("guest_progress_after_marker_verified") is not True
            or prior.get("original_init_executed") is not False
            or prior.get("android_init_started") is not False
            or prior.get("safe_to_flash") is not False):
        raise ValueError("Matching stock EXT4 diagnostic transition required")
    old = [d for d in prior["disks"] if d["name"]=="runtime"]
    if len(old)!=1 or old[0]["sha256"] != runtime["payload_sha256"] or old[0]["bytes"] != runtime["payload_bytes"]:
        raise ValueError("Runtime APEX differs from stock control")


def verify_system(stock, fixture):
    if (fixture.get("service_fixture") is not True
            or fixture.get("diagnostic_init_substitution") is not None
            or fixture["policy_sha256"] == stock["policy_sha256"]
            or fixture["experimental_linker_config_sha256"] != sha(CONFIG)):
        raise ValueError("Separate service system fixture required")
    old,new = stock["verified_system_entries"], fixture["verified_system_entries"]
    def executable_files(entries):
        return {path:{k:v for k,v in info.items() if k!="context"}
                for path,info in entries.items()
                if path in ("system/bin","system/lib64") or path.startswith(("system/bin/","system/lib64/"))}
    if executable_files(old) != executable_files(new):
        raise ValueError("System executable payloads changed from stock control")
    for path,label in ((FILE,LABEL),(SERVICE,SERVICE_LABEL)):
        info = new[path[1:]]
        if info["context"] != label or info["type"]!="regular":
            raise ValueError("Dedicated fixture executable label required")
    if new["system/etc/ld.config.txt"]["sha256"] != sha(CONFIG):
        raise ValueError("Experimental linker config content mismatch")


def inspect_console(log,records,plan):
    lines = log.replace(b"\r\n",b"\n").splitlines()
    end = labels.PREFIX+f"PASS count={len(plan)} android=not-started".encode()
    if lines.count(START)!=1 or lines.count(end)!=1:
        raise ValueError("Missing fixture policy/label diagnostics")
    if [x for x in lines if x.startswith(labels.PREFIX)] != (
            [START]+[labels.PREFIX+b"path="+p.encode()+b" context="+v.encode()
                     for p,v in plan.items()]+[end]):
        raise ValueError("Unexpected fixture effective labels")
    prefix = lines[:lines.index(end)+1]
    normalized = b"\n".join(labels.START if x==START else x for x in prefix)
    evidence = labels.inspect_console(normalized,records,plan)
    if [x for x in lines if x.startswith(b"r800-ext4-service:")] != [RAM,EXEC]:
        raise ValueError("Unexpected RAM and exec handover")
    modes = [b"r800-ext4-exec: "+d["name"].encode()+b" noexec="+
             (b"0" if d["name"] in ("system","runtime") else b"1") for d in records]
    if [x for x in lines if x.startswith(b"r800-ext4-exec:")] != modes:
        raise ValueError("Unexpected service execution flags")
    markers = [x for x in lines if x.startswith((b"r800-property-service:",b"r800-property-client:"))]
    if any(x.startswith(b"r800-ext4-transition:") for x in lines):
        raise ValueError("Unexpected static transition markers")
    if markers != MARKERS:
        raise ValueError("Unexpected original libinit/client sequence")
    mount_end = disks.PREFIX+f"PASS count={len(records)} policy=not-loaded android=not-started".encode()
    if not (lines.index(modes[-1]) < lines.index(mount_end) < lines.index(RAM) <
            lines.index(START) < lines.index(end) < lines.index(EXEC) < lines.index(MARKERS[0])):
        raise ValueError("Service handover out of order")
    if any(x.startswith(HEARTBEAT_PREFIX) for x in lines[:lines.index(MARKERS[-1])]):
        raise ValueError("Heartbeat before client completion")
    stdout = inspect_stdout(log, ("kernel","init","client"),
        (disks.EXPECTED.rstrip(b"\n"), EXEC, MARKERS[1]),
        (modes[0], MARKERS[0], MARKERS[2]))
    return {**evidence,**stdout,"fixture_policy_loaded_reported":True,"stock_policy":False,
            "production_policy":False,"current_domain_reported":"u:r:init:s0",
            "init_domain_entered":True,"mount_noexec_requested":False,
            "system_runtime_exec_reported":True,"property_service_started":True,
            "client_transition_reported":True,"socket_set_update_reported":True,
            "read_only_status_reported":0x000b,"mac_denied_status_reported":0x0018,
            "negative_value_unchanged_reported":True,"android_init_started":False}


def run(a):
    kernel = verify_baseline(a.baseline,a.kernel)
    cfg = read_bounded_json(a.config_evidence)
    policy,records = disks.inventory(a,service=True)
    stock = disks.report(a.stock_system_report,"ANDROID_SYSTEM_EXT4_LABELED_STATIC_ONLY")
    fixture = disks.report(a.system_report,"ANDROID_SYSTEM_EXT4_SERVICE_STATIC_ONLY")
    extra = disks.report(a.context_report,"ANDROID_CONTEXT_PARTITIONS_STATIC_ONLY")
    runtime = disks.report(a.runtime_report,"ANDROID_RUNTIME_APEX_PAYLOAD_PRESERVED_ONLY")
    prior = disks.report(a.transition_report,"VIRT_ANDROID_EXT4_DIAGNOSTIC_INIT_DOMAIN_ONLY")
    verify_prior(prior,kernel,cfg["config_sha256"],stock,runtime)
    verify_system(stock,fixture)
    root = a.product_out.resolve(strict=True)
    checked = audit_fixture(root,a.checkfc,a.analyze)
    if checked["policy_sha256"] != policy or checked["file_contexts_sha256"] != fixture["platform_file_contexts_sha256"] or checked["property_contexts_sha256"] != fixture["property_contexts_sha256"]:
        raise ValueError("Fixture policy/context identity mismatch")
    blob = snapshot(regular(root,checked["policy_path"]),MAX_POLICY)
    if sha(blob)!=policy:
        raise ValueError("Fixture policy changed")
    plan = labels.label_plan(fixture,extra,runtime)
    origin = disks.report(a.origin_report,ORIGIN_STATUS)
    binding = bind_system(fixture,origin)
    if (binding["runtime_apex_sha256"] != runtime["apex_sha256"] or
            binding["runtime_payload_sha256"] != runtime["payload_sha256"]):
        raise ValueError("Runtime image differs from recorded build origin")
    resolution = audit_linker_resolution(fixture,runtime)
    abi = audit_elf_abi(fixture,runtime,a.system_dir/"system.ext4",a.runtime_dir/"runtime.ext4",a.readelf)
    nosuid = require_ready(blob, "fixture", a.seinfo, a.sesearch)
    access = audit_exec_access(blob,fixture,extra,runtime,"fixture",a.sesearch)
    manifest = "".join(p+" "+v+"\n" for p,v in plan.items()).encode("ascii")
    if len(manifest)>256*1024:
        raise ValueError("Label manifest exceeds bounds")
    result = disks.run(a,expected_inventory=(policy,records),service=True,
        extra_entries=[("galwear-policy",(0o100400,blob,0,0)),
                       ("galwear-labels.list",(0o100400,manifest,0,0))],
        label_parser=lambda log,actual:inspect_console(log,actual,plan))
    return {**result,"nosuid_policy_prerequisites":nosuid,"exec_access_advisory":access,"linker_resolution_static":resolution,"elf_abi_advisory":abi,"artifact_origin_binding":binding,"stock_policy_sha256":stock["policy_sha256"],
            "fixture_audit":checked,"label_manifest_sha256":sha(manifest),
            "prior_transition_archive_sha256":prior["archive_sha256"],
            "experimental_linker_config_sha256":sha(CONFIG),
            "namespace_resolution_tested_by_service_execution":True,
            "genuine_android_linkerconfig_tested":False,"safe_to_flash":False}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ("system-dir","system-report","stock-system-report","context-dir","context-report",
                 "runtime-dir","runtime-report","kernel","baseline","config-evidence","init",
                 "compile-evidence","product-out","checkfc","analyze","transition-report","origin-report","out-dir","report"):
        p.add_argument("--"+name,type=Path,required=True)
    p.add_argument("--readelf",default="readelf")
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
