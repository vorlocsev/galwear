#!/usr/bin/env python3
"""Bind a pinned stock extraction report to an exact local build input.

This checks the reported byte chain and the actual raw image, not Samsung
authenticity. The original archive is not opened by this verifier.
"""
import argparse
from pathlib import Path

from r800_donor_preflight import digest, MAX_DONOR
from r800_extract_stock_donor import ROLES
from r800_extract_super import require
from r800_graphics_donor_binding import checkout_sha
from r800_partition_identity import filesystem
from r800_review_handover import read_report, sha, LIMIT
from r800_android_userspace_preflight import read_regular
from r800_stage_adaptation_layer import valid_pin

INPUTS={"tizen":("r800-rootfs","rootfs.img"),
        "j4":("j4-vendor","vendor.img")}
FALSE_FLAGS=("donor_model_verified","donor_authenticity_verified",
             "runtime_verified","hardware_tested","safe_to_flash")


def bounded_identity(row):
    require(isinstance(row,dict) and set(row)=={"bytes","sha256"} and
            type(row["bytes"]) is int and 0<row["bytes"]<=MAX_DONOR and
            valid_pin(row["sha256"]),"Invalid stock byte identity")
    return row


def describe(report,image_pin,report_pin,archive_pin,build_input,source_sha):
    require(build_input in INPUTS and all(valid_pin(p) for p in
            (image_pin,report_pin,archive_pin)),"Explicit stock input and SHA-256 pins required")
    role,filename=INPUTS[build_input]
    require(report.get("source_sha")==source_sha and
            report.get("status")=="STOCK_PARTITION_CANDIDATE_ONLY","Evidence scope mismatch")
    require(report.get("schema")=="galwear-r800-stock-donor-v1" and
            report.get("role")==role and report.get("member") in ROLES[role] and
            all(report.get(k) is False for k in FALSE_FLAGS),"Unexpected stock extraction scope")
    archive=bounded_identity(report["archive"])
    member=bounded_identity(report["member_identity"])
    expanded=bounded_identity(report["decompressed_identity"])
    require(archive["sha256"]==archive_pin and member["bytes"]<=archive["bytes"],
            "Stock archive pin or size mismatch")
    if not report["member"].endswith(".lz4"):
        require(member==expanded,"Uncompressed stock member mismatch")
    partition=report["partition"]
    require(isinstance(partition,dict) and set(partition)=={"file","bytes","sha256"} and
            partition["file"]==filename,"Stock partition role mismatch")
    raw=bounded_identity({k:partition[k] for k in ("bytes","sha256")})
    n=report["normalization"]
    require(n["source_sha256"]==expanded["sha256"] and n["source_bytes"]==expanded["bytes"] and
            n["raw_sha256"]==raw["sha256"] and n["raw_bytes"]==raw["bytes"],
            "Stock normalization chain mismatch")
    require(raw["sha256"]==image_pin,"Stock build input bytes mismatch")
    fs=report["filesystem"]
    require(isinstance(fs,dict) and fs.get("kind")=="EXT4","Stock filesystem mismatch")
    if role=="j4-vendor":
        require(isinstance(report["android_identity"],dict) and
                report["android_identity"].get("filesystem")==fs,"Stock vendor identity mismatch")
    else:
        require(report["android_identity"] is None,"Unexpected Tizen Android identity")
    return {"schema":"galwear-r800-stock-build-binding-v1",
            "status":"STOCK_REPORT_AND_RAW_INPUT_MATCH_ONLY","source_sha":source_sha,
            "build_input":build_input,"role":role,"report_sha256":report_pin,
            "reported_archive_sha256":archive_pin,"image":raw,"filesystem":fs,
            "archive_rehashed":False,"donor_authenticity_verified":False,
            "hardware_tested":False,"safe_to_flash":False}


def verify(image,image_pin,report_path,report_pin,archive_pin,build_input,source_sha):
    checkout_sha(source_sha)
    image,report_path=(Path(p).absolute() for p in (image,report_path))
    require(all(p.resolve(strict=True)==p and p.is_file() for p in
                (image,report_path)),"Canonical stock input files required")
    report=read_report(report_path,report_pin,source_sha,"STOCK_PARTITION_CANDIDATE_ONLY")
    result=describe(report,image_pin,report_pin,archive_pin,build_input,source_sha)
    require(digest(image,MAX_DONOR)==result["image"],"Stock build input bytes mismatch")
    require(filesystem(image)==result["filesystem"],"Stock filesystem mismatch")
    require(digest(image,MAX_DONOR)==result["image"] and
            sha(read_regular(report_path,LIMIT))==report_pin,
            "Stock build input or report changed")
    checkout_sha(source_sha)
    return result


def main():
    import json
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input",choices=INPUTS,required=True)
    for name in ("image","report"):
        parser.add_argument("--"+name,type=Path,required=True)
        parser.add_argument("--"+name+"-sha256",required=True)
    parser.add_argument("--archive-sha256",required=True)
    parser.add_argument("--source-sha",required=True)
    a=parser.parse_args()
    print(json.dumps(verify(a.image,a.image_sha256,a.report,a.report_sha256,
                           a.archive_sha256,a.input,a.source_sha),indent=2,sort_keys=True))


if __name__=="__main__":
    main()
