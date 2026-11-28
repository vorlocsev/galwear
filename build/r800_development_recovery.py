#!/usr/bin/env python3
"""Bind a development installation plan to local, independently pinned recovery inputs.

Offline structural review only. No package generation, device connection,
partition write, backup creation, restoration or authorization to flash.
"""
import argparse
import json
from pathlib import Path
import sys

from r800_installation_layout import prepare
from r800_review_handover import read_report, sha, LIMIT
from r800_android_userspace_preflight import read_regular
from r800_donor_preflight import digest
from r800_stage_adaptation_layer import valid_pin
from r800_graphics_donor_binding import checkout_sha
from r800_extract_super import require

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"installer"))
from r800_safety import parse_pit_strict, validate_r800_pit
from r800_recovery_readiness import (parse_all_pit_partitions,
    validate_factory_boundaries, FAILURE_HANDLING)

ARTIFACTS=("dzImage","dzImage-recovery","ramdisk.img","ramdisk-recovery.img")
NAMES={"p15":"csc.img","p17":"user.img","p16":"system-data.img","p18":"rootfs.img"}
MAX_PIT=64*1024
MAX_ARTIFACT=64*1024**2


def pit_review(raw):
    require(28<=len(raw)<=MAX_PIT,"PIT size outside review limit")
    validate_r800_pit(parse_pit_strict(raw))
    factory=validate_factory_boundaries(raw)
    entries=parse_all_pit_partitions(raw)
    by_name={r["flash_filename"]:r for r in entries if r["flash_filename"]}
    chosen={n:by_name[n] for n in (*NAMES.values(),*ARTIFACTS)}
    for name,row in chosen.items():
        require(row["blocks"]>0 and not row["protected"],"Invalid target PIT entry: "+name)
        require(sum(x["identifier"]==row["identifier"] for x in entries)==1,
                "Ambiguous PIT identifier: "+name)
        for other in entries:
            if other["index"]==row["index"] or other["device_type"]!=row["device_type"] or not other["blocks"]:
                continue
            require(max(row["offset"],other["offset"])>=min(row["offset"]+row["blocks"],
                    other["offset"]+other["blocks"]),"Possible PIT range overlap: "+name)
    return chosen,factory


def review_recovery(tree,tree_pin,layout_path,layout_pin,pit_path,pit_pin,artifacts,pins,source_sha,
                    *,capacity_path=None,capacity_pin=None):
    checkout_sha(source_sha)
    require(set(artifacts)==set(pins)==set(ARTIFACTS) and
            all(valid_pin(v) for v in pins.values()) and valid_pin(pit_pin),
            "Four explicit original recovery artifact pins and PIT pin required")
    layout_path,pit_path=(Path(p).absolute() for p in (layout_path,pit_path))
    artifacts={n:Path(p).absolute() for n,p in artifacts.items()}
    inputs=(layout_path,pit_path,*artifacts.values())
    require(len(set(inputs))==len(inputs) and all(p.resolve(strict=True)==p for p in inputs),
            "Distinct canonical local evidence files required")
    layout=read_report(layout_path,layout_pin,source_sha,"HOLD_HARDWARE_UNVERIFIED")
    expected=prepare(tree,tree_pin,source_sha,capacity_path=capacity_path,capacity_pin=capacity_pin)
    require(layout==expected,"Installation layout differs from recomputed tree")
    raw=read_regular(pit_path,MAX_PIT)
    require(sha(raw)==pit_pin,"PIT pin mismatch")
    chosen,factory=pit_review(raw)
    observed={}
    for name,path in sorted(artifacts.items()):
        row=digest(path,MAX_ARTIFACT)
        require(row["sha256"]==pins[name],"Recovery artifact pin mismatch: "+name)
        require(row["bytes"]<=chosen[name]["blocks"]*512,
                "Recovery artifact exceeds assumed PIT capacity: "+name)
        observed[name]=row
    require(len(set(pins.values()))==len(pins),"Recovery artifact roles must not share identical bytes")
    mapping={}
    for part,name in NAMES.items():
        r=chosen[name]
        capacity=r["blocks"]*512
        logical=layout["storage_estimate"]["partitions"].get(part,{}).get("logical_file_bytes")
        mapping[part]={"pit_filename":name,"pit_identifier":r["identifier"],
                       "assumed_partition_bytes":capacity,"planned_logical_bytes":logical,
                       "logical_size_within_assumed_partition":None if logical is None else logical<=capacity}
    require(sha(read_regular(pit_path,MAX_PIT))==pit_pin and
            sha(read_regular(layout_path,LIMIT))==layout_pin and
            all(digest(artifacts[n],MAX_ARTIFACT)==row for n,row in observed.items()),
            "Recovery evidence changed during review")
    checkout_sha(source_sha)
    return {"schema":"galwear-r800-development-recovery-v1","status":"HOLD_HARDWARE_UNVERIFIED",
            "source_sha":source_sha,"integrated_evidence_sha256":tree_pin,
            "installation_layout_sha256":layout_pin,"pit_sha256":pit_pin,
            "artifact_sha256":observed,"partition_mapping":mapping,
            "factory_partition_bounds":factory,"assumed_sector_bytes":512,
            "pit_linux_partition_mapping_verified":False,
            "artifact_format_or_authenticity_verified":False,
            "device_identity_verified":False,"factory_backup_verified":False,
            "rollback_artifacts_verified":False,"recovery_tested":False,
            "wired_recovery_verified":False,"wireless_recovery_verified":False,
            "failure_handling":FAILURE_HANDLING,"installation_authorized":False,
            "safe_to_flash":False}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for n in ("tree","layout","pit","output","capacity"):
        p.add_argument("--"+n,type=Path,required=n!="capacity")
    for n in ("tree-sha256","layout-sha256","pit-sha256","source-sha","capacity-sha256"):
        p.add_argument("--"+n,required=n!="capacity-sha256")
    p.add_argument("--artifact",nargs=3,action="append",required=True,
                   metavar=("ROLE","LOCAL_FILE","SHA256"))
    a=p.parse_args()
    require(len(a.artifact)==len(ARTIFACTS) and len({r[0] for r in a.artifact})==len(ARTIFACTS),
            "Exactly four unique artifact roles required")
    inputs={n:Path(f) for n,f,h in a.artifact}
    pins={n:h for n,f,h in a.artifact}
    repo=Path(__file__).resolve().parents[1]
    require(not any(a.output.resolve().is_relative_to(root) for root in (repo,a.tree.resolve())),
            "Report must be outside source and input trees")
    report=review_recovery(a.tree,a.tree_sha256,a.layout,a.layout_sha256,a.pit,a.pit_sha256,
                           inputs,pins,a.source_sha,capacity_path=a.capacity,capacity_pin=a.capacity_sha256)
    with a.output.open("x",encoding="utf-8") as stream:
        json.dump(report,stream,indent=2,sort_keys=True)
        stream.write("\n")
    print(report["status"],"safe_to_flash=false")


if __name__=="__main__":
    main()
