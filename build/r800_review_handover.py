#!/usr/bin/env python3
"""Read-only final development-tree handover review, not boot authorization.

QEMU observations may be attached only from the same local Tizen runtime.
Reference execution, a timeout and a clean ELF list never count as a
successful daemon startup. No mounts, state creation or device access.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile

from r800_android_userspace_preflight import read_regular
from r800_donor_preflight import digest, MAX_DONOR
from r800_graphics_donor_binding import checkout_sha
from r800_stage_adaptation_layer import DEVICE, RUNTIME_REQUIRED, valid_pin, MAX_FILE
from r800_stage_development_tree import ANDROID, inspect_pair, verify_overlay
from r800_tizen_config_layout import layout, verify_dir, MOUNTPOINTS
from r800_payload_candidate import ASSET_SIZES
from r800_runtime_loader_qemu import LOCAL
from r800_runtime_entry_qemu import LOCAL_COMMANDS
from r800_verify_tizen_stage import unique_keys
from r800_extract_super import require

LIMIT=16*1024**2
KERNEL={"development-boot/"+name for name in
        ("Image","r800.dtb","effective.config","init","initramfs.generated")}
REPORTS={"integrated-development-evidence.json","development-tree-evidence.json"}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def read_report(path,pin,source_sha,status):
    raw=read_regular(path,LIMIT)
    require(valid_pin(pin) and sha(raw)==pin,"Evidence pin mismatch: "+path.name)
    report=json.loads(raw,object_pairs_hook=unique_keys)
    require(report.get("source_sha")==source_sha and report.get("status")==status and
            report.get("safe_to_flash") is False,"Evidence scope mismatch: "+path.name)
    return report


def verify_inventory(root,files,dirs):
    require(len(files)<=2048,"Tree inventory exceeds budget")
    expected_dirs=set(dirs)
    for name,row in files.items():
        require(isinstance(name,str) and len(name)<=1024 and all(
            re.fullmatch(r"[A-Za-z0-9_.@+-]+",p) and p not in (".","..") for p in name.split("/")),
            "Unsafe tree member")
        require(valid_pin(row.get("sha256")) and type(row.get("bytes")) is int and
                0<row["bytes"]<=(MAX_DONOR if name in ANDROID else MAX_FILE) and
                row.get("mode") in ("0o400","0o644","0o755"),"Invalid member metadata: "+name)
        expected_dirs.update(p.as_posix() for p in Path(name).parents if p.as_posix()!=".")
    seen=set()
    seen_dirs=set()
    pending=[root]
    while pending:
        with os.scandir(pending.pop()) as items:
            for entry in items:
                path=Path(entry.path)
                rel=path.relative_to(root).as_posix()
                st=entry.stat(follow_symlinks=False)
                if stat.S_ISDIR(st.st_mode):
                    require(rel in expected_dirs and not st.st_mode&0o7000,"Unexpected tree directory: "+rel)
                    verify_dir(path,rel,dirs)
                    seen_dirs.add(rel)
                    pending.append(path)
                else:
                    require(stat.S_ISREG(st.st_mode) and st.st_nlink==1 and
                            (rel in files or rel in REPORTS),"Unexpected tree entry: "+rel)
                    seen.add(rel)
                    if rel in files:
                        row=files[rel]
                        require(oct(stat.S_IMODE(st.st_mode))==row["mode"] and
                                digest(path,MAX_DONOR if rel in ANDROID else MAX_FILE)==
                                {"bytes":row["bytes"],"sha256":row["sha256"]},
                                "Tree member changed: "+rel)
    require(seen==set(files)|REPORTS and seen_dirs==expected_dirs,"Tree inventory mismatch")


def runtime_observations(loader,entry,runtime_pin,source_sha):
    require(loader.get("schema")=="galwear-r800-loader-qemu-v1" and
            loader.get("status")=="ARM32_LOADER_LIST_PASS" and
            entry.get("schema")=="galwear-r800-runtime-entry-qemu-v1" and
            entry.get("status")=="LOCAL_STARTUP_OBSERVATIONS_ONLY",
            "Local runtime observation scope required")
    for report in (loader,entry):
        require(report.get("scope")==LOCAL and report.get("source_sha")==source_sha and
                report.get("runtime_evidence_sha256")==runtime_pin and
                all(report.get(k) is False for k in ("daemon_startup_verified",
                    "dlopen_runtime_verified","gnss_runtime_verified","hardware_tested","safe_to_flash")),
                "Reference or stale runtime observation rejected")
    require(set(LOCAL_COMMANDS)<=set(loader.get("checks",{})) and
            set(entry.get("observations",{}))==set(LOCAL_COMMANDS),"Incomplete daemon observation inventory")
    for row in loader["checks"].values():
        require(row.get("exit_code")==0,"Loader observation failed")
    for row in entry["observations"].values():
        require(valid_pin(row.get("log_sha256")) and row.get("classification") in
                ("BOUNDED_TIMEOUT_REVIEW","EXIT_ZERO_REVIEW","NONZERO_EXIT_REVIEW"),
                "Invalid daemon observation")
    return "OBSERVED_NOT_ACCEPTED"


def review(root,pin,source_sha,*,runtime_path=None,runtime_pin=None,loader_path=None,loader_pin=None,
           entry_path=None,entry_pin=None):
    checkout_sha(source_sha)
    root=Path(root).absolute()
    require(root.resolve(strict=True)==root and root.is_dir(),"Canonical integrated tree required")
    i=read_report(root/"integrated-development-evidence.json",pin,source_sha,
                  "FUNCTIONAL_KERNEL_AND_ANDROID_TREE_STAGED_ONLY")
    u=read_report(root/"development-tree-evidence.json",i["userspace_evidence_sha256"],source_sha,
                  "ANDROID_DEVICE_DEVELOPMENT_TREE_STAGED_ONLY")
    require(i.get("kernel_boot_profile")=="DEVELOPMENT_FUNCTIONAL_UNTESTED" and
            i.get("storage_write_capable") is True and i.get("boot_container_created") is False and
            all(i.get(k) is False for k in ("payload_complete","android_handover_tested","hardware_tested")),
            "Unexpected kernel/boot scope")
    k=i["kernel_files"]
    files=u["files"]
    require(set(k)==KERNEL and set(DEVICE)|RUNTIME_REQUIRED|ANDROID<=set(files) and
            not set(k)&set(files) and i["userspace_files"]==len(files) and
            i["userspace_bytes"]==u["total_bytes"]==sum(r["bytes"] for r in files.values()),
            "Integrated inventory identity mismatch")
    dirs=layout(u,files)
    verify_inventory(root,{**files,**k},dirs)
    with tempfile.TemporaryDirectory(prefix="r800-handover-review-") as tmp:
        scratch=Path(tmp)
        system=root/"r800dev/android/system.img"
        vendor=root/"r800-android/vendor.img"
        require(inspect_pair(system,vendor,scratch)==u["android_inspection"],
                "Android image inspection changed")
        require(verify_overlay(vendor,files,scratch)==u["vendor_overlay_matches"],
                "Vendor overlay inspection changed")
    observations="NOT_TESTED"
    supplied=(runtime_path,runtime_pin,loader_path,loader_pin,entry_path,entry_pin)
    if any(v is not None for v in supplied):
        require(all(v is not None for v in supplied) and valid_pin(runtime_pin),
                "Provide all local runtime observation inputs together")
        t=read_report(Path(runtime_path),runtime_pin,source_sha,"LOCAL_TIZEN_ELF_FIRMWARE_RUNTIME_STAGED_ONLY")
        require(t.get("schema")=="galwear-r800-tizen-runtime-v1" and t.get("chroot_mountpoints")==dirs and
                set(t["files"])=={n for n,row in files.items() if row.get("layer")=="tizen-runtime"} and
                all(all(row.get(key)==files[n].get(key) for key in ("bytes","sha256","mode"))
                    for n,row in t["files"].items()),"Runtime evidence does not match final tree")
        l=read_report(Path(loader_path),loader_pin,source_sha,"ARM32_LOADER_LIST_PASS")
        e=read_report(Path(entry_path),entry_pin,source_sha,"LOCAL_STARTUP_OBSERVATIONS_ONLY")
        require(e.get("loader_evidence_sha256")==loader_pin,"Entry/loader binding mismatch")
        observations=runtime_observations(l,e,runtime_pin,source_sha)
    missing_assets=[name for name in sorted(ASSET_SIZES)
                    if "r800dev/"+name not in files]
    # The current development assembler does not include installation state.
    # Do not create a marker or a persistent image to satisfy this review.
    checkout_sha(source_sha)
    return {"schema":"galwear-r800-handover-review-v1","status":"HOLD_HARDWARE_UNVERIFIED",
            "source_sha":source_sha,"integrated_evidence_sha256":pin,
            "checks":{"tree_inventory":"PASS","android_pair":"STATIC_PASS",
                      "vendor_overlay":"STATIC_PASS",
                      "chroot_mountpoints":"STATIC_PASS" if dirs==MOUNTPOINTS else "MISSING",
                      "local_runtime_startup":observations,
                      "kernel_boot":"NOT_TESTED","android_switch_root":"NOT_TESTED",
                      "android_framework_boot":"NOT_TESTED","gnss":"NOT_TESTED"},
            "missing_display_assets":missing_assets,
            "blockers":["Original donor provenance and complete Tizen plugin/configuration review",
                        "Partition capacity, installation/recovery contract and persistent-state policy",
                        "Actual kernel boot, switch_root and Android framework startup",
                        "Physical HAL, GNSS, power and recovery acceptance"],
            "runtime_observations_bound_to_final_tree":observations=="OBSERVED_NOT_ACCEPTED",
            "daemon_startup_verified":False,"android_handover_tested":False,
            "hardware_tested":False,"safe_to_flash":False}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--tree",type=Path,required=True)
    p.add_argument("--tree-sha256",required=True)
    p.add_argument("--source-sha",required=True)
    p.add_argument("--output",type=Path,required=True)
    for name in ("runtime","loader","entry"):
        p.add_argument("--"+name,type=Path)
        p.add_argument("--"+name+"-sha256")
    a=p.parse_args()
    require(not a.output.resolve().is_relative_to(a.tree.resolve()),"Report must be outside tree")
    report=review(a.tree,a.tree_sha256,a.source_sha,runtime_path=a.runtime,runtime_pin=a.runtime_sha256,
                  loader_path=a.loader,loader_pin=a.loader_sha256,entry_path=a.entry,entry_pin=a.entry_sha256)
    with a.output.open("x",encoding="utf-8") as stream:
        json.dump(report,stream,indent=2,sort_keys=True)
        stream.write("\n")
    print(report["status"])


if __name__=="__main__":
    main()
