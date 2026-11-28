#!/usr/bin/env python3
"""Describe an offline installation layout; never issue device write commands.

The manifest is a review artifact only. It does not create boot containers,
installation payloads, persistent images, backups or boot selection markers.
"""
import argparse
import json
from pathlib import Path
import re

from r800_review_handover import review, read_report, sha, LIMIT
from r800_storage_estimate import placement
from r800_android_userspace_preflight import read_regular
from r800_extract_super import require
from r800_graphics_donor_binding import checkout_sha


FORBIDDEN={"BOOT_ANDROID","persistent.img","userdata.img","userdata-blank.img.gz",
           "data.img.gz","RESET_DATA","DEV","STAY","SLEEP","CPUIDLE_DEEP",
           "OVERLAY","TZTRACE","GPU_SCALE","DIAG","hook.sh","accounts.db",
           "accounts_ce.db","accounts_de.db","wpa_supplicant.conf","bt_config.conf",
           ".mac.info"}


def plan(files,dirs,kernel_files):
    mapped,directories=placement(files,dirs)
    result={}
    for part,rows in sorted(mapped.items()):
        members={}
        for name in sorted(rows):
            require(all(re.fullmatch(r"[A-Za-z0-9_.@+-]+",p) and p not in (".","..")
                        for p in name.split("/")) and not any(p in FORBIDDEN for p in name.split("/")),
                    "Unsafe or stateful deployment member: "+name)
            row=files[name]
            mode="0o644" if name.endswith(".img") else row["mode"]
            require(mode in ("0o644","0o755"),"Unexpected intended file mode: "+name)
            members[name]={"source":name,"bytes":row["bytes"],"sha256":row["sha256"],
                           "intended_mode":mode}
        for name in directories[part]:
            require(all(re.fullmatch(r"[A-Za-z0-9_.@+-]+",p) and p not in (".","..")
                        for p in name.split("/")) and not any(p in FORBIDDEN for p in name.split("/")),
                    "Unsafe deployment directory: "+name)
        result[part]={"files":members,"directories":sorted(directories[part]),
                      "conflict_policy":"HOLD_IF_EXISTING_TARGET","apply_authorized":False}
    return {"partition_layout":result,
            "boot_components_build_only":{n:kernel_files[n] for n in
                ("development-boot/Image","development-boot/r800.dtb")},
            "preserve_partitions":["p16","p18"],
            "excluded_build_provenance":sorted(n for n in files if n.startswith("vendor/")),
            "recovery_requirements":[
                "Exact device identity and independently verified partition map",
                "Verified original boot and recovery artifacts for this device",
                "Verified existing target state and explicit conflict resolution",
                "Independently reviewed recovery procedure and hardware recovery acceptance",
                "Measured available blocks and inodes including userdata policy"],
            "rollback_artifacts_verified":False,"recovery_tested":False,
            "payload_created":False,"boot_container_created":False,
            "installation_authorized":False,"safe_to_flash":False}


def prepare(root,pin,source_sha,*,capacity_path=None,capacity_pin=None):
    root=Path(root).absolute()
    handover=review(root,pin,source_sha,capacity_path=capacity_path,capacity_pin=capacity_pin)
    integrated=read_report(root/"integrated-development-evidence.json",pin,source_sha,
                           "FUNCTIONAL_KERNEL_AND_ANDROID_TREE_STAGED_ONLY")
    userspace=read_report(root/"development-tree-evidence.json",integrated["userspace_evidence_sha256"],
                          source_sha,"ANDROID_DEVICE_DEVELOPMENT_TREE_STAGED_ONLY")
    layout=plan(userspace["files"],userspace.get("chroot_mountpoints",{}),integrated["kernel_files"])
    checkout_sha(source_sha)
    return {"schema":"galwear-r800-installation-layout-v1","status":"HOLD_HARDWARE_UNVERIFIED",
            "source_sha":source_sha,"integrated_evidence_sha256":pin,
            "userspace_evidence_sha256":integrated["userspace_evidence_sha256"],
            "handover_review_sha256":sha(json.dumps(handover,sort_keys=True,separators=(",",":")).encode()),
            "storage_estimate":handover["storage_estimate"],
            "missing_display_assets":handover["missing_display_assets"],
            **layout}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tree",type=Path,required=True)
    parser.add_argument("--tree-sha256",required=True)
    parser.add_argument("--source-sha",required=True)
    parser.add_argument("--capacity",type=Path)
    parser.add_argument("--capacity-sha256")
    parser.add_argument("--output",type=Path,required=True)
    args=parser.parse_args()
    repo=Path(__file__).resolve().parents[1]
    require(not any(args.output.resolve().is_relative_to(p) for p in (args.tree.resolve(),repo)),
            "Report must be outside source and input trees")
    report=prepare(args.tree,args.tree_sha256,args.source_sha,capacity_path=args.capacity,
                   capacity_pin=args.capacity_sha256)
    with args.output.open("x",encoding="utf-8") as stream:
        json.dump(report,stream,indent=2,sort_keys=True)
        stream.write("\n")
    print(report["status"],"safe_to_flash=false")


if __name__=="__main__":
    main()
