#!/usr/bin/env python3
"""Read-only pinned local donor manifest and explicit development build entrypoint.

Paths are relative to one canonical local workspace outside the checkout.
No downloads, donor discovery, copying archives, or flash authorization.
"""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath

from r800_android_userspace_preflight import read_regular
from r800_build_local_development import build, preflight, stock_bindings, sha
from r800_bind_pixel_system import verify as verify_pixel
from r800_ndk_pins import verify as verify_ndk, KEYS as NDK_KEYS
from r800_display_asset_layer import load_assets
from r800_extract_super import require
from r800_graphics_donor_binding import checkout_sha
from r800_stage_adaptation_layer import valid_pin
from r800_verify_tizen_stage import unique_keys

LIMIT=1024*1024
ROLES={"kernel","components","system","base","j4","effects","tizen","closure","ndk"}
SCHEMA="galwear-r800-local-donor-manifest-v1"


def local_path(root,value):
    require(isinstance(value,str) and 0<len(value)<=1024 and
            "\\" not in value and ":" not in value and
            all(p not in ("",".","..") for p in value.split("/")) and
            not PurePosixPath(value).is_absolute(),"Expected safe workspace-relative path")
    path=root/value
    require(path.resolve(strict=True)==path and path.is_relative_to(root),
            "Noncanonical or escaped workspace path")
    return path


def load(root,manifest,pin,source_sha):
    checkout_sha(source_sha)
    root,manifest=Path(root).absolute(),Path(manifest).absolute()
    repo=Path(__file__).resolve().parents[1]
    require(root.resolve(strict=True)==root and root.is_dir() and
            not root.is_relative_to(repo) and not repo.is_relative_to(root),
            "Separate canonical local workspace required")
    require(manifest.resolve(strict=True)==manifest and manifest.is_relative_to(root),
            "Manifest must be inside workspace")
    raw=read_regular(manifest,LIMIT)
    require(valid_pin(pin) and sha(raw)==pin,"Donor manifest SHA-256 mismatch")
    data=json.loads(raw,object_pairs_hook=unique_keys)
    require(isinstance(data,dict) and set(data)=={"schema","source_sha","inputs","evidence","xtra_abi","assets"} and
            data["schema"]==SCHEMA and data["source_sha"]==source_sha,
            "Unexpected manifest schema or source SHA")
    rows=data["inputs"]
    require(isinstance(rows,dict) and set(rows)==ROLES,"Complete manifest input roles required")
    paths,pins={},{}
    ndk_pins=None
    for name,row in rows.items():
        fields={"path"} if name=="ndk" else {"path","sha256"}
        if name=="ndk" and isinstance(row,dict) and "tools_sha256" in row:
            fields.add("tools_sha256")
        require(isinstance(row,dict) and set(row)==fields,"Unexpected input fields: "+name)
        paths[name]=local_path(root,row["path"])
        if name=="ndk" and "tools_sha256" in row:
            ndk_pins=row["tools_sha256"]
            require(isinstance(ndk_pins,dict) and set(ndk_pins)==NDK_KEYS and
                    all(valid_pin(v) for v in ndk_pins.values()),"Invalid NDK selected tool pins")
        if name!="ndk":
            require(valid_pin(row["sha256"]),"Explicit input SHA-256 required: "+name)
            pins[name]=row["sha256"]
    require(len(set(paths.values()))==len(paths),"Distinct manifest input paths required")
    evidence=data["evidence"]
    require(isinstance(evidence,dict) and set(evidence)=={"system","j4","tizen"},
            "All three donor reports required in managed mode")
    reports={}
    for name,row in evidence.items():
        fields={"path","sha256"} if name=="system" else {"path","sha256","archive_sha256"}
        require(isinstance(row,dict) and set(row)==fields and
                all(valid_pin(row[k]) for k in fields-{"path"}),"Invalid donor report pin: "+name)
        reports[name]=(local_path(root,row["path"]),row["sha256"])
        if name!="system":
            reports[name]+= (row["archive_sha256"],)
    require(len({v[0] for v in reports.values()})==3,"Distinct donor reports required")
    assets=data["assets"]
    asset_path=asset_pin=None
    if assets is not None:
        require(isinstance(assets,dict) and set(assets)=={"path","sha256"} and
                valid_pin(assets["sha256"]),"Invalid asset manifest")
        asset_path=local_path(root,assets["path"])
        asset_pin=assets["sha256"]
    require(type(data["xtra_abi"]) is int and data["xtra_abi"] in (0,1,2),"Invalid XTRA ABI")
    require(sha(read_regular(manifest,LIMIT))==pin,"Donor manifest changed")
    checkout_sha(source_sha)
    return {"paths":paths,"pins":pins,"stock_evidence":{n:reports[n] for n in ("j4","tizen")},
            "pixel_evidence":reports["system"],"xtra_abi":data["xtra_abi"],
            "assets":asset_path,"assets_sha":asset_pin,"ndk_pins":ndk_pins}


def check(config,output,source_sha):
    paths,pins=config["paths"],config["pins"]
    preflight(paths,pins,output,source_sha)
    ndk=None if config["ndk_pins"] is None else verify_ndk(paths["ndk"],config["ndk_pins"])
    pixel=verify_pixel(paths["system"],pins["system"],*config["pixel_evidence"],source_sha)
    stock=stock_bindings(paths,pins,config["stock_evidence"],source_sha)
    if config["assets"] is not None:
        require(not Path(output).resolve().is_relative_to(config["assets"]),"Output inside asset input")
        load_assets(config["assets"],config["assets_sha"])
    return {"schema":"galwear-r800-managed-donor-check-v1","status":"MANAGED_INPUT_PINS_MATCH_ONLY",
            "source_sha":source_sha,"input_sha256":pins,"stock_donor_bindings":stock,
            "pixel_system_binding":pixel,"ndk_identity_verified":False,
            "ndk_selected_tool_evidence":ndk,
            "ndk_selected_tool_status":"NOT_SUPPLIED" if ndk is None else ndk["status"],
            "base_vendor_origin_verified":False,"effects_origin_verified":False,
            "donor_authenticity_verified":False,"hardware_tested":False,"safe_to_flash":False}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace",type=Path,required=True)
    parser.add_argument("--manifest",type=Path,required=True)
    parser.add_argument("--manifest-sha256",required=True)
    parser.add_argument("--source-sha",required=True)
    parser.add_argument("--output",type=Path,required=True)
    parser.add_argument("--mode",choices=("check","build"),default="check")
    a=parser.parse_args()
    cfg=load(a.workspace,a.manifest,a.manifest_sha256,a.source_sha)
    if a.mode=="check":
        result=check(cfg,a.output,a.source_sha)
        result["local_manifest_sha256"]=a.manifest_sha256
    else:
        # The existing builder independently checks all pins and evidence
        # before and after assembly, and publishes only after readiness.
        require(cfg["ndk_pins"] is not None,"Managed build requires explicit selected NDK tool pins")
        result=build(cfg["paths"],cfg["pins"],a.output,a.source_sha,cfg["xtra_abi"],
                     assets=cfg["assets"],assets_sha=cfg["assets_sha"],
                     stock_evidence=cfg["stock_evidence"],pixel_evidence=cfg["pixel_evidence"],
                     ndk_pins=cfg["ndk_pins"],
                     managed_manifest=(a.workspace,a.manifest,a.manifest_sha256))
    print(json.dumps(result,indent=2,sort_keys=True))


if __name__=="__main__":
    main()
