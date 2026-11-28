#!/usr/bin/env python3
"""Build a local GalWear development tree from same-head compiled inputs.

The kernel and device binaries must already be compiled for this checkout.
Original donors remain outside Git. No download, flash container, persistent
state or hardware execution. The vendor recipe requires a private Linux root
environment; this is not a release builder.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import tempfile

from r800_android_userspace_preflight import read_regular
from r800_build_local_android import build as build_android
from r800_stage_device_layer import assemble as stage_device
from r800_stage_tizen_runtime import assemble as stage_runtime
from r800_stage_adaptation_layer import assemble as stage_adaptation, valid_pin
from r800_stage_integrated_development import assemble as stage_integrated, kernel_inputs
from r800_donor_preflight import digest, MAX_DONOR, verify_components
from r800_graphics_donor_binding import checkout_sha
from r800_extract_super import require
from r800_verify_tizen_stage import MANIFEST, unique_keys
from r800_display_asset_layer import load_assets
from r800_bind_stock_donor import INPUTS as STOCK_INPUTS, verify as verify_stock
from r800_bind_pixel_system import verify as verify_pixel
from r800_ndk_pins import verify as verify_ndk

MAX_REPORT=16*1024**2
MAX_FILE=64*1024**2


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def bind(root, name, report, source_sha, status):
    require(report.get("source_sha")==source_sha and report.get("status")==status and
            report.get("safe_to_flash") is False,"Unexpected stage scope: "+name)
    raw=read_regular(root/name,MAX_REPORT)
    require(json.loads(raw,object_pairs_hook=unique_keys)==report,"Stage evidence mismatch: "+name)
    return sha(raw)


def preflight(paths, pins, output, source_sha):
    checkout_sha(source_sha)
    repo=Path(__file__).resolve().parents[1]
    require(set(paths)=={"kernel","components","system","base","j4","effects","tizen","closure","ndk"},
            "Complete explicit local inputs required")
    require(set(pins)==set(paths)-{"ndk"} and all(valid_pin(v) for v in pins.values()),
            "Explicit SHA-256 pins required for all donors and build manifests")
    paths={k:Path(v).absolute() for k,v in paths.items()}
    for k,p in paths.items():
        require(p.resolve(strict=True)==p,"Noncanonical input: "+k)
        require(p.is_dir() if k in ("kernel","components","closure","ndk") else p.is_file(),
                "Wrong input type: "+k)
    output=Path(output).absolute()
    require(not output.exists() and not output.is_symlink() and
            not any(output.resolve().is_relative_to(p) for p in (repo,*paths.values())),
            "Fresh output outside input trees required")
    require(len({pins[n] for n in ("system","base","j4","tizen")})==4,
            "Distinct original donor image pins required")
    for name in ("system","base","j4","effects","tizen"):
        require(digest(paths[name],MAX_FILE if name=="effects" else MAX_DONOR)["sha256"]==pins[name],
                "Donor pin mismatch: "+name)
    for name,manifest in (("kernel","development-kernel-evidence.json"),
                          ("components","component-evidence.json"),("closure",MANIFEST)):
        require(sha(read_regular(paths[name]/manifest,MAX_REPORT))==pins[name],
                "Build input manifest pin mismatch: "+name)
    verify_components(paths["components"],source_sha)
    return paths,output


def stock_bindings(paths,pins,stock_evidence,source_sha):
    if stock_evidence is None:
        return {}
    require(set(stock_evidence)==set(STOCK_INPUTS),"Supply both stock donor reports together")
    results={}
    for name in sorted(STOCK_INPUTS):
        report,report_pin,archive_pin=stock_evidence[name]
        results[name]=verify_stock(paths[name],pins[name],report,report_pin,archive_pin,name,source_sha)
    return results


def build(paths,pins,output,source_sha,xtra_abi=0,*,assets=None,assets_sha=None,stock_evidence=None,pixel_evidence=None,ndk_pins=None):
    require(type(xtra_abi) is int and xtra_abi in (0,1,2),"Explicit supported XTRA ABI required")
    p,output=preflight(paths,pins,output,source_sha)
    ndk_evidence=None if ndk_pins is None else verify_ndk(p["ndk"],ndk_pins)
    stock=stock_bindings(p,pins,stock_evidence,source_sha)
    pixel=None if pixel_evidence is None else verify_pixel(p["system"],pins["system"],*pixel_evidence,source_sha)
    require((assets is None)==(assets_sha is None),"Asset directory and manifest pin must be supplied together")
    if assets is not None:
        assets=Path(assets).absolute()
        require(not output.resolve().is_relative_to(assets),"Output inside asset input")
        load_assets(assets,assets_sha)
    with tempfile.TemporaryDirectory(dir=output.parent,prefix="r800-local-build-") as tmp:
        work=Path(tmp)
        # Reject diagnostic/stale kernel before expensive vendor/runtime work.
        raw,k,_=kernel_inputs(p["kernel"],pins["kernel"],source_sha,work)
        device=work/"device"
        runtime=work/"runtime"
        adaptation=work/"adaptation"
        android=work/"android-build"
        result=work/"result"
        d=stage_device(p["components"],device,source_sha,assets=assets,assets_sha=assets_sha)
        dp=bind(device,"device-layer-evidence.json",d,source_sha,"COMPILED_DEVICE_LAYER_STAGED_ONLY")
        require(d["component_manifest_sha256"]==pins["components"],"Device component pin mismatch")
        require(d.get("assets_manifest_sha256")==assets_sha,"Device display asset pin mismatch")
        t=stage_runtime(p["tizen"],pins["tizen"],p["closure"],pins["closure"],
                        p["ndk"],runtime,source_sha,xtra_abi)
        tp=bind(runtime,"tizen-runtime-evidence.json",t,source_sha,"LOCAL_TIZEN_ELF_FIRMWARE_RUNTIME_STAGED_ONLY")
        require(t["tizen_image_sha256"]==pins["tizen"] and t["closure_manifest_sha256"]==pins["closure"],
                "Runtime donor pin mismatch")
        a=stage_adaptation(device,dp,runtime,tp,adaptation,source_sha)
        ap=bind(adaptation,"adaptation-layer-evidence.json",a,source_sha,"DEVICE_AND_LOCAL_TIZEN_ADAPTATION_STAGED_ONLY")
        require(a["device_manifest_sha256"]==dp and a["runtime_manifest_sha256"]==tp,
                "Adaptation input pin mismatch")
        b=build_android(p["components"],p["system"],pins["system"],p["base"],pins["base"],
                        p["j4"],pins["j4"],p["effects"],pins["effects"],android,source_sha)
        bp=bind(android,"android-build-evidence.json",b,source_sha,"LOCAL_ANDROID_LAYER_BUILT_STATIC_ONLY")
        require(b["component_manifest_sha256"]==pins["components"] and
                b["original_donor_sha256"]=={n:pins[n] for n in ("system","base","j4","effects")},
                "Android input pin mismatch")
        android_pin=b["android_layer_evidence_sha256"]
        require(valid_pin(android_pin),"Missing Android layer evidence pin")
        i=stage_integrated(p["kernel"],pins["kernel"],adaptation,ap,android/"android",
                           android_pin,result,source_sha)
        ip=bind(result,"integrated-development-evidence.json",i,source_sha,
                "FUNCTIONAL_KERNEL_AND_ANDROID_TREE_STAGED_ONLY")
        from r800_review_handover import review
        handover=review(result,ip,source_sha)
        require(handover["status"]=="HOLD_HARDWARE_UNVERIFIED" and handover["safe_to_flash"] is False,
                "Unexpected handover review scope")
        require(i["kernel_evidence_sha256"]==pins["kernel"],"Integrated kernel pin mismatch")
        # No stage may silently change any of the original donor pins.
        preflight(p,pins,output,source_sha)
        if ndk_evidence is not None:
            require(verify_ndk(p["ndk"],ndk_pins)==ndk_evidence,"NDK selected tools changed during assembly")
        evidence=work/"evidence"
        evidence.mkdir()
        reports=[(p["kernel"],"development-kernel-evidence.json",pins["kernel"]),
                 (device,"device-layer-evidence.json",dp),
                 (runtime,"tizen-runtime-evidence.json",tp),
                 (adaptation,"adaptation-layer-evidence.json",ap),
                 (android,"android-build-evidence.json",bp),
                 (android/"android","android-layer-evidence.json",android_pin)]
        copied={}
        if pixel is not None:
            require(verify_pixel(p["system"],pins["system"],*pixel_evidence,source_sha)==pixel,
                    "Pixel donor evidence changed")
            data=read_regular(Path(pixel_evidence[0]),MAX_REPORT)
            require(sha(data)==pixel["report_sha256"],"Pixel donor report changed")
            (evidence/"pixel-system-evidence.json").write_bytes(data)
            copied["pixel-system-evidence.json"]=pixel["report_sha256"]
        require(stock_bindings(p,pins,stock_evidence,source_sha)==stock,"Stock donor evidence changed")
        for name,row in stock.items():
            report_name="stock-"+name+"-evidence.json"
            data=read_regular(Path(stock_evidence[name][0]),MAX_REPORT)
            require(sha(data)==row["report_sha256"],"Stock donor report changed")
            (evidence/report_name).write_bytes(data)
            copied[report_name]=row["report_sha256"]
        for root,name,pin in reports:
            data=read_regular(root/name,MAX_REPORT)
            require(sha(data)==pin,"Stage evidence changed: "+name)
            (evidence/name).write_bytes(data)
            copied[name]=pin
        # The Android producer also preserves its recipe and adaptation reports.
        for name,pin in (("system-adaptation-evidence.json",b["system_adaptation_evidence_sha256"]),
                         ("vendor-build-evidence.json",b["vendor_build_evidence_sha256"])):
            data=read_regular(android/"evidence"/name,MAX_REPORT)
            require(sha(data)==pin,"Android provenance changed: "+name)
            (evidence/name).write_bytes(data)
            copied[name]=pin
        vendor=json.loads(read_regular(evidence/"vendor-build-evidence.json",MAX_REPORT),object_pairs_hook=unique_keys)
        for name,pin in vendor["recipe_evidence_sha256"].items():
            require(name in ("input-evidence.json","recipe-preflight.json","merged-vendor-graph.json"),
                    "Unexpected vendor recipe report")
            data=read_regular(android/"evidence"/name,MAX_REPORT)
            require(sha(data)==pin,"Vendor recipe evidence changed")
            (evidence/name).write_bytes(data)
            copied[name]=pin
        if assets is not None:
            load_assets(assets,assets_sha)
            asset_raw=read_regular(assets/"assets-evidence.json",1024*1024)
            require(sha(asset_raw)==assets_sha,"Asset evidence changed")
            (evidence/"assets-evidence.json").write_bytes(asset_raw)
            copied["assets-evidence.json"]=assets_sha
        handover_raw=(json.dumps(handover,indent=2,sort_keys=True)+"\n").encode()
        (evidence/"handover-review.json").write_bytes(handover_raw)
        copied["handover-review.json"]=sha(handover_raw)
        summary={"schema":"galwear-r800-local-development-build-v1",
                 "status":"LOCAL_GALWEAR_DEVELOPMENT_TREE_BUILT_STATIC_ONLY",
                 "source_sha":source_sha,"input_sha256":pins,"xtra_abi":xtra_abi,
                 "assets_manifest_sha256":assets_sha,
                 "stock_donor_bindings":stock,
                 "pixel_system_binding":pixel,
                 "ndk_selected_tool_evidence":ndk_evidence,
                 "stage_evidence_sha256":copied,"integrated_evidence_sha256":ip,
                 "missing_inputs_and_gates":i["missing_inputs_and_gates"],
                 "kernel_and_components_compiled_by_this_command":False,
                 "donor_authenticity_verified":False,"full_runtime_built":False,
                 "wear_os_verified":False,"payload_complete":False,
                 "android_handover_tested":False,"hardware_tested":False,"safe_to_flash":False}
        publish=work/"publish"
        publish.mkdir()
        os.rename(result,publish/"development")
        os.rename(evidence,publish/"evidence")
        summary_raw=(json.dumps(summary,indent=2,sort_keys=True)+"\n").encode()
        (publish/"local-build-evidence.json").write_bytes(summary_raw)
        # Recompute the complete evidence chain from the private final tree
        # before it is exposed to the caller. A structural HOLD is expected;
        # it is not acceptance of installation or hardware boot.
        from r800_development_readiness import readiness
        final=readiness(publish,sha(summary_raw),source_sha)
        require(final["checks"]["stage_chain"]=="STATIC_PASS" and
                final["integrated_evidence_sha256"]==ip and
                final["status"]=="HOLD_HARDWARE_UNVERIFIED" and
                final["safe_to_flash"] is False,
                "Final readiness verification failed")
        checkout_sha(source_sha)
        require(not output.exists() and not output.is_symlink(),"Output already exists")
        os.rename(publish,output)
    return summary


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    names=("kernel","components","system","base","j4","effects","tizen","closure","ndk")
    for name in names:
        parser.add_argument("--"+name,type=Path,required=True)
        if name!="ndk":
            parser.add_argument("--"+name+"-sha256",required=True)
    parser.add_argument("--source-sha",required=True)
    parser.add_argument("--output",type=Path,required=True)
    parser.add_argument("--xtra-abi",type=int,choices=(0,1,2),default=0)
    parser.add_argument("--assets",type=Path)
    parser.add_argument("--assets-sha256")
    parser.add_argument("--stock-evidence",nargs=4,action="append",
                        metavar=("INPUT","REPORT","REPORT_SHA256","ARCHIVE_SHA256"))
    parser.add_argument("--pixel-evidence",nargs=2,metavar=("REPORT","REPORT_SHA256"))
    args=parser.parse_args()
    stock=None
    if args.stock_evidence is not None:
        require(len(args.stock_evidence)==len(STOCK_INPUTS) and
                {n for n,_,_,_ in args.stock_evidence}==set(STOCK_INPUTS),
                "Exactly one tizen and one j4 stock evidence required")
        stock={n:(Path(p),h,a) for n,p,h,a in args.stock_evidence}
    paths={n:getattr(args,n) for n in names}
    pins={n:getattr(args,n+"_sha256") for n in names if n!="ndk"}
    print(build(paths,pins,args.output,args.source_sha,args.xtra_abi,assets=args.assets,assets_sha=args.assets_sha256,stock_evidence=stock,
                pixel_evidence=args.pixel_evidence)["status"],"safe_to_flash=false")


if __name__=="__main__":
    main()
