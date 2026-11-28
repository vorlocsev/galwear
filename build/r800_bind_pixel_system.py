#!/usr/bin/env python3
"""Bind a pinned RWDC Pixel raw-system report to a local development input.

No archive re-extraction, AVB verification, donor authentication or runtime
acceptance. Android 15 and EROFS are outside this Android 11 EXT4 pipeline.
"""
import argparse
import json
from pathlib import Path

from r800_extract_pixel_factory import FACTORY_SHA256, MAX_ARCHIVE
from r800_bind_stock_donor import bounded_identity
from r800_extract_super import require
from r800_graphics_donor_binding import checkout_sha
from r800_donor_preflight import digest, MAX_DONOR
from r800_partition_identity import filesystem
from r800_review_handover import read_report, sha, LIMIT
from r800_android_userspace_preflight import read_regular
from r800_stage_adaptation_layer import valid_pin

STATUS="SELECTED_PIXEL_RAW_DONOR_PARTITIONS_ONLY"
FLAGS=("system_adaptation_verified","donor_authenticity_verified",
       "wear_os_runtime_verified","r800_compatibility_verified","hardware_tested","safe_to_flash")


def scope(row,status,flags):
    require(row.get("status")==status and all(row.get(k) is False for k in flags),
            "Unexpected Pixel evidence scope")


def image_identity(row):
    return bounded_identity({k:row[k] for k in ("bytes","sha256")})


def normalized(row,origin):
    require(row["source_sha256"]==origin["sha256"] and row["source_bytes"]==origin["bytes"],
            "Pixel normalization source mismatch")
    raw=bounded_identity({"bytes":row["raw_bytes"],"sha256":row["raw_sha256"]})
    require(row["format"] in ("raw","android_sparse_v1") and
            (row["format"]!="raw" or raw==origin),"Pixel normalization format mismatch")
    return raw


def describe(report,image_pin,report_pin,source_sha):
    require(valid_pin(image_pin) and valid_pin(report_pin),"Explicit Pixel SHA-256 pins required")
    scope(report,STATUS,FLAGS)
    require(report.get("schema")=="galwear-r800-pixel-raw-donor-v1" and
            report.get("source_sha")==source_sha and
            report.get("factory_sha256")==FACTORY_SHA256 and
            report.get("documented_factory_pin_matched") is True,"Expected pinned RWDC factory report")
    factory=report["factory_extraction"]
    scope(factory,"PIXEL_DONOR_EXTRACTED_ONLY",
          ("system_adaptation_verified","vendor_compatibility_verified","safe_to_flash"))
    require(factory["factory_sha256"]==FACTORY_SHA256,"Pixel factory pin mismatch")
    nested=factory["nested_zip"]
    require(type(nested["bytes"]) is int and 0<nested["bytes"]<=MAX_ARCHIVE and
            valid_pin(nested["sha256"]),"Invalid nested ZIP identity")
    parts=report["partitions"]
    names=set(parts)&{"system","system_a","system_b"}
    require(len(names)==1,"Exactly one Pixel system partition required")
    name=next(iter(names))
    row=parts[name]
    raw=image_identity(row)
    require(row["file"]==name+".img" and raw["sha256"]==image_pin,"Pixel system input mismatch")
    fs=row["filesystem"]
    require(fs["kind"]=="EXT4" and fs["partition_bytes"]==raw["bytes"],
            "Current development system requires EXT4")
    ident=row["identity"]
    require(ident.get("schema")=="galwear-r800-partition-identity-v1" and
            ident.get("source_sha")==source_sha and ident.get("partition")==name and
            ident.get("image_sha256")==image_pin and ident.get("filesystem")==fs and
            all(ident.get(k) is False for k in ("donor_authenticity_verified",
                "wear_os_runtime_verified","hardware_tested","safe_to_flash")),
            "Pixel partition identity mismatch")
    mode,slot=report["mode"],report["metadata_slot"]
    if mode=="direct":
        require(name=="system" and slot is None and report["super_extraction"] is None,
                "Invalid direct Pixel system selection")
        origin=image_identity(factory["images"]["system.img"])
        require(normalized(row["provenance"],origin)==raw,"Pixel direct raw mismatch")
    else:
        require(mode=="super" and type(slot) is int and slot in (0,1) and
                name in ("system",("system_a","system_b")[slot]),"Pixel super slot mismatch")
        sup=report["super_extraction"]
        scope(sup,"SUPER_SELECTED_PARTITIONS_EXTRACTED_ONLY",
              ("all_slots_verified","filesystem_contents_verified","avb_verified",
               "wear_os_runtime_verified","hardware_tested","safe_to_flash"))
        require(sup.get("schema")=="galwear-r800-super-extraction-v1" and
                sup.get("source_sha")==source_sha and sup["metadata_slot"]==slot and
                valid_pin(sup["metadata_sha256"]),"Pixel super evidence mismatch")
        normalized(sup["input"],image_identity(factory["images"]["super.img"]))
        require(sup["partitions"][name]=={"file":name+".img",**raw} and
                row["provenance"]=={"source":"super.img","metadata_slot":slot,
                                   "raw_bytes":raw["bytes"],"raw_sha256":raw["sha256"]},
                "Pixel logical partition chain mismatch")
    return {"schema":"galwear-r800-pixel-system-binding-v1",
            "status":"PIXEL_REPORT_AND_RAW_SYSTEM_MATCH_ONLY","source_sha":source_sha,
            "report_sha256":report_pin,"reported_factory_sha256":FACTORY_SHA256,
            "partition":name,"mode":mode,"metadata_slot":slot,"image":raw,"filesystem":fs,
            "archive_rehashed":False,"donor_authenticity_verified":False,
            "hardware_tested":False,"safe_to_flash":False}


def verify(image,image_pin,report_path,report_pin,source_sha):
    checkout_sha(source_sha)
    image,report_path=(Path(p).absolute() for p in (image,report_path))
    require(all(p.resolve(strict=True)==p and p.is_file() for p in (image,report_path)),
            "Canonical Pixel input files required")
    report=read_report(report_path,report_pin,source_sha,STATUS)
    result=describe(report,image_pin,report_pin,source_sha)
    require(digest(image,MAX_DONOR)==result["image"] and filesystem(image)==result["filesystem"],
            "Pixel system bytes or filesystem mismatch")
    require(digest(image,MAX_DONOR)==result["image"] and
            sha(read_regular(report_path,LIMIT))==report_pin,"Pixel input or report changed")
    checkout_sha(source_sha)
    return result


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ("image","report"):
        p.add_argument("--"+name,type=Path,required=True)
        p.add_argument("--"+name+"-sha256",required=True)
    p.add_argument("--source-sha",required=True)
    a=p.parse_args()
    print(json.dumps(verify(a.image,a.image_sha256,a.report,a.report_sha256,a.source_sha),
                     indent=2,sort_keys=True))


if __name__=="__main__":
    main()
