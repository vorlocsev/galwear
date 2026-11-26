#!/usr/bin/env python3
"""Independently rebind an extended static candidate to a verified donor image."""
import argparse
import json
import os
from pathlib import Path, PurePosixPath
import re
import struct
import subprocess

from r800_tzlite_manifest import inventory, read_file, MANIFEST, MAX_MANIFEST
from r800_tzlite_legacy_image_scope import inspect_image
from r800_tzlite_metadata_plan import digest
from r800_tzlite_audit import TARGETS, MOUNTPOINTS, REQUIRED_TREES, closure_problems
from r800_tizen_gnss_preflight import CONFIGS, config_evidence
from r800_tizen_dependencies import audit


def verify(root,image,image_sha,review_sha,stage_sha):
    if any(not isinstance(v,str) or not re.fullmatch(r"[0-9a-f]{64}",v)
           for v in (image_sha,review_sha,stage_sha)):
        raise ValueError("Expected three lowercase SHA-256 digests")
    if root.is_symlink():
        raise ValueError("Expected nonsymlink candidate root")
    root=root.resolve(strict=True)
    if root==Path("/") or not root.is_dir():
        raise ValueError("Expected isolated candidate directory")
    if image.resolve(strict=True).is_relative_to(root):
        raise ValueError("Donor image must be outside candidate")
    path=root/MANIFEST
    info,raw=read_file(path,MAX_MANIFEST,capture=True)
    if info["sha256"]!=stage_sha or info["mode"]!="0o600":
        raise ValueError("Extended stage manifest digest or mode mismatch")
    recorded=json.loads(raw)
    if (not isinstance(recorded,dict)
            or recorded.get("schema")!="r800-tzlite-extended-stage-v1"
            or recorded.get("status")!="EXTENDED_STATIC_CANDIDATE_ONLY"
            or recorded.get("image_sha256")!=image_sha
            or recorded.get("review_manifest_sha256")!=review_sha
            or recorded.get("source_and_stage_audited") is not True
            or any(recorded.get(k) is not False for k in ("full_configuration_copied",
                  "plugins_complete","ownership_preserved","runtime_verified","safe_to_flash"))):
        raise ValueError("Invalid extended stage manifest")
    tree=inventory(root)
    if tree!=recorded.get("tree") or tree["root_mode"]!="0o700":
        raise ValueError("Extended stage inventory or root mode mismatch")
    source=inspect_image(image,image_sha,extended_manifest=True)
    review=source["extended_manifest"]
    plugins=source["extra_plugin_audit"]
    if (source.get("snapshot_verified") is not True or source.get("image_sha256")!=image_sha
            or digest(review)!=review_sha or source["extended_manifest_sha256"]!=review_sha
            or review["status"]!="REVIEW_REQUIRED" or plugins["problems"]):
        raise ValueError("Extended donor review binding failed")
    closure=plugins["dependency_evidence"]
    files={n:v for n,v in review["files"].items() if v["category"] in ("AUDITED_ELF","KNOWN_CONFIG")}
    aliases=review["aliases"]
    if set(files)!=set(closure["files"])|set(CONFIGS):
        raise ValueError("Extended source subset incomplete")
    dirs=set(MOUNTPOINTS+REQUIRED_TREES)
    for name in set(files)|set(aliases)|set(dirs):
        dirs.update(str(p) for p in PurePosixPath(name).parents if str(p)!="/")
    entries=tree["entries"]
    if set(entries)!=set(files)|set(aliases)|dirs:
        raise ValueError("Extended stage path set differs from source subset")
    if (recorded.get("included_files")!=sorted(files)
            or recorded.get("excluded_unreviewed_data")!=sorted(set(review["files"])-set(files))
            or recorded.get("review_items")!=review["review_items"]):
        raise ValueError("Extended stage scope differs from source review")
    for name,item in files.items():
        actual=entries[name]
        allowed=("0o644","0o755") if item["category"]=="AUDITED_ELF" else ("0o600",)
        if (actual["kind"]!="file" or actual["mode"] not in allowed
                or any(actual[k]!=item[k] for k in ("bytes","sha256"))):
            raise ValueError("Extended stage file differs from source:"+name)
    for name in dirs:
        rec=entries[name]
        if rec["kind"]!="directory" or int(rec["mode"],8)&0o7022:
            raise ValueError("Extended stage directory mode review:"+name)
    for name,item in aliases.items():
        expected=os.path.relpath(root/item["canonical"].lstrip("/"),
                                 (root/name.lstrip("/")).parent)
        if entries[name]!={"kind":"symlink","target":expected}:
            raise ValueError("Extended stage alias differs from audited target:"+name)
    targets=tuple(dict.fromkeys(TARGETS+tuple(plugins["candidates"])))
    actual=audit(root,targets)
    if closure_problems(actual) or any(actual[k]!=closure[k] for k in
                                      ("files","aliases","symbol_candidates","relocation_review_objects")):
        raise ValueError("Extended stage ELF closure differs from donor")
    configs=config_evidence(root)
    if configs["problems"] or configs["files"]!={n:{k:files[n][k] for k in ("bytes","sha256")} for n in CONFIGS}:
        raise ValueError("Extended stage configuration review")
    if inventory(root)!=tree or read_file(path,MAX_MANIFEST)[0]!=info:
        raise ValueError("Extended stage changed during verification")
    return {"schema":"r800-tzlite-extended-verify-v1","status":"EXTENDED_STATIC_IMAGE_MATCH_ONLY",
            "image_sha256":image_sha,"review_manifest_sha256":review_sha,
            "stage_manifest_sha256":stage_sha,"snapshot_verified":True,
            "file_count":len(files),"alias_count":len(aliases),
            "extra_plugin_count":len(plugins["candidates"]),
            "excluded_unreviewed_data_count":len(set(review["files"])-set(files)),
            "review_items":review["review_items"],"problems":[],
            "donor_authenticity_verified":False,"ownership_verified":False,
            "xattrs_verified":False,"runtime_verified":False,"safe_to_flash":False}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--root",type=Path,required=True)
    p.add_argument("--image",type=Path,required=True)
    p.add_argument("--image-sha256",required=True)
    p.add_argument("--review-sha256",required=True)
    p.add_argument("--stage-sha256",required=True)
    a=p.parse_args()
    try:
        report=verify(a.root,a.image,a.image_sha256,a.review_sha256,a.stage_sha256)
    except (OSError,ValueError,struct.error,subprocess.SubprocessError,RecursionError) as exc:
        report={"schema":"r800-tzlite-extended-verify-v1","status":"REVIEW_REQUIRED",
                "problems":[str(exc)],"safe_to_flash":False}
    print(json.dumps(report,indent=2,sort_keys=True))
    return 2 if report["problems"] else 0


if __name__=="__main__":
    raise SystemExit(main())
