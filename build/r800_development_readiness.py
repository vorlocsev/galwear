#!/usr/bin/env python3
"""Read-only combined development readiness; never an installation authorization."""
import argparse
import json
from pathlib import Path
import tempfile

from r800_review_handover import review, read_report, sha, LIMIT
from r800_installation_layout import prepare
from r800_development_recovery import review_recovery, ARTIFACTS
from r800_android_userspace_preflight import read_regular
from r800_stage_adaptation_layer import valid_pin
from r800_verify_tizen_stage import unique_keys
from r800_graphics_donor_binding import checkout_sha
from r800_extract_super import require
from r800_bind_stock_donor import INPUTS as STOCK_INPUTS, describe as describe_stock
from r800_bind_pixel_system import STATUS as PIXEL_STATUS, describe as describe_pixel
from r800_base_vendor_identity import review_saved as review_base
from r800_linux_assembly_environment import saved_environment, read_pinned
from r800_ndk_pins import REVISION as NDK_REVISION, KEYS as NDK_KEYS, BIN as NDK_BIN, LIMIT as NDK_LIMIT

STAGES={
    "development-kernel-evidence.json":"DEVELOPMENT_KERNEL_COMPONENTS_STATIC_ONLY",
    "device-layer-evidence.json":"COMPILED_DEVICE_LAYER_STAGED_ONLY",
    "tizen-runtime-evidence.json":"LOCAL_TIZEN_ELF_FIRMWARE_RUNTIME_STAGED_ONLY",
    "adaptation-layer-evidence.json":"DEVICE_AND_LOCAL_TIZEN_ADAPTATION_STAGED_ONLY",
    "android-build-evidence.json":"LOCAL_ANDROID_LAYER_BUILT_STATIC_ONLY",
    "android-layer-evidence.json":"PREPARED_ANDROID_EXT4_PAIR_STAGED_ONLY",
    "system-adaptation-evidence.json":"SYSTEM_AS_ROOT_MOUNTPOINT_PREPARED_ONLY",
    "vendor-build-evidence.json":"LOCAL_VENDOR_CANDIDATE_OVERLAY_MATCH_ONLY",
    "handover-review.json":"HOLD_HARDWARE_UNVERIFIED",
}
RECIPE={"input-evidence.json","recipe-preflight.json","merged-vendor-graph.json"}


def canonical(report):
    return json.dumps(report,sort_keys=True,separators=(",",":")).encode()


def chain(summary,reports,i,u):
    p=summary["stage_evidence_sha256"]
    inputs=summary["input_sha256"]
    k=reports["development-kernel-evidence.json"]
    d=reports["device-layer-evidence.json"]
    t=reports["tizen-runtime-evidence.json"]
    a=reports["adaptation-layer-evidence.json"]
    b=reports["android-build-evidence.json"]
    al=reports["android-layer-evidence.json"]
    s=reports["system-adaptation-evidence.json"]
    v=reports["vendor-build-evidence.json"]
    require(set(inputs)=={"kernel","components","system","base","j4","effects","tizen","closure"} and
            all(valid_pin(x) for x in inputs.values()),"Invalid original input pins")
    require(i["kernel_evidence_sha256"]==p["development-kernel-evidence.json"]==inputs["kernel"] and
            d["component_manifest_sha256"]==b["component_manifest_sha256"]==
            v["component_manifest_sha256"]==inputs["components"] and
            t["tizen_image_sha256"]==inputs["tizen"] and t["closure_manifest_sha256"]==inputs["closure"],
            "Kernel, component or Tizen chain mismatch")
    require(a["device_manifest_sha256"]==p["device-layer-evidence.json"] and
            a["runtime_manifest_sha256"]==p["tizen-runtime-evidence.json"] and
            u["adaptation_manifest_sha256"]==p["adaptation-layer-evidence.json"] and
            u["android_manifest_sha256"]==b["android_layer_evidence_sha256"]==p["android-layer-evidence.json"] and
            b["system_adaptation_evidence_sha256"]==p["system-adaptation-evidence.json"] and
            b["vendor_build_evidence_sha256"]==p["vendor-build-evidence.json"] and
            v["recipe_evidence_sha256"]=={n:p[n] for n in RECIPE},"Stage evidence chain mismatch")
    require(b["original_donor_sha256"]=={n:inputs[n] for n in ("system","base","j4","effects")} and
            v["donor_sha256"]=={**{n:inputs[n] for n in ("base","j4","effects")},
                               "system":s["system"]["sha256"]},"Android donor chain mismatch")
    kernel_pins={"Image":k["components"]["kernel_sha256"],"r800.dtb":k["components"]["dtb_sha256"],
                 "effective.config":k["config_sha256"],"init":k["init_sha256"],
                 "initramfs.generated":k["generated_cpio"]["archive_sha256"]}
    require({n:row["sha256"] for n,row in i["kernel_files"].items()}==
            {"development-boot/"+n:h for n,h in kernel_pins.items()} and
            i["kernel_files"]["development-boot/Image"]["bytes"]==k["components"]["kernel_bytes"] and
            i["kernel_files"]["development-boot/r800.dtb"]["bytes"]==k["components"]["dtb_bytes"],
            "Final kernel files differ from original evidence")
    require(s["original"]["sha256"]==inputs["system"] and
            al["files"]=={"r800dev/android/system.img":{**s["system"],"mode":"0o400"},
                          "r800-android/vendor.img":{**v["vendor"],"mode":"0o400"}},
            "Final Android images differ from original evidence")
    require(not set(d["files"])&set(t["files"]) and not set(a["files"])&set(al["files"]) and
            set(a["files"])==set(d["files"])|set(t["files"]) and
            set(u["files"])==set(a["files"])|set(al["files"]),"Stage inventory mismatch")
    for report,layer in ((d,"device"),(t,"tizen-runtime"),(al,"android")):
        for name,row in report["files"].items():
            require(u["files"][name].get("layer")==layer and
                    all(row[key]==u["files"][name][key] for key in ("bytes","sha256","mode")),
                    "Final member differs from source stage: "+name)
    require(all(a["files"][n]==u["files"][n] for n in a["files"]) and
            b["files"]==al["files"] and b["overlay_matches"]==v["overlay_matches"]==u["vendor_overlay_matches"],
            "Adaptation or overlay chain mismatch")
    asset=summary.get("assets_manifest_sha256")
    require(asset==d.get("assets_manifest_sha256")==a.get("assets_manifest_sha256")==
            u.get("assets_manifest_sha256")==p.get("assets-evidence.json"),"Display asset chain mismatch")
    return True


def stock_inventory(summary):
    stock=summary.get("stock_donor_bindings",{})
    require(isinstance(stock,dict) and (not stock or set(stock)==set(STOCK_INPUTS)),
            "Incomplete stock donor binding inventory")
    return {"stock-"+n+"-evidence.json" for n in stock}


def stock_chain(summary,evidence,source_sha):
    stock=summary.get("stock_donor_bindings",{})
    stock_inventory(summary)
    for name,row in stock.items():
        filename="stock-"+name+"-evidence.json"
        pin=summary["stage_evidence_sha256"][filename]
        report=read_report(evidence/filename,pin,source_sha,"STOCK_PARTITION_CANDIDATE_ONLY")
        expected=describe_stock(report,summary["input_sha256"][name],pin,
                               row["reported_archive_sha256"],name,source_sha)
        require(row==expected,"Saved stock binding differs from extraction evidence: "+name)
    return "SAVED_REPORT_CHAIN_ONLY" if stock else "NOT_SUPPLIED"


def pixel_chain(summary,evidence,source_sha):
    pixel=summary.get("pixel_system_binding")
    if pixel is None:
        return "NOT_SUPPLIED"
    require(isinstance(pixel,dict),"Invalid Pixel binding")
    name="pixel-system-evidence.json"
    pin=summary["stage_evidence_sha256"][name]
    report=read_report(evidence/name,pin,source_sha,PIXEL_STATUS)
    expected=describe_pixel(report,summary["input_sha256"]["system"],pin,source_sha)
    require(expected==pixel,"Saved Pixel binding differs from extraction evidence")
    return "SAVED_REPORT_CHAIN_ONLY"


def ndk_chain(summary):
    ndk=summary.get("ndk_selected_tool_evidence")
    if ndk is None:
        return None
    require(isinstance(ndk,dict) and
            ndk.get("schema")=="galwear-r800-ndk-selected-tools-v1" and
            ndk.get("status")=="SELECTED_NDK_TOOL_PINS_MATCH_ONLY" and
            ndk.get("revision")==NDK_REVISION and
            all(ndk.get(k) is False for k in ("complete_ndk_verified","host_libraries_verified",
                  "upstream_authenticity_verified","safe_to_flash")),"Unexpected NDK evidence scope")
    rows=ndk["files"]
    require(isinstance(rows,dict) and set(rows)==NDK_KEYS,"Incomplete NDK selected file inventory")
    for name,row in rows.items():
        require(isinstance(row,dict) and set(row)=={"bytes","sha256","resolved"} and
                type(row["bytes"]) is int and 0<row["bytes"]<=(65536 if name=="source.properties" else NDK_LIMIT)
                and valid_pin(row["sha256"]),"Invalid selected NDK file identity")
        target=row["resolved"]
        require(isinstance(target,str) and all(p not in ("",".","..") for p in target.split("/"))
                and "\\" not in target and ":" not in target and
                (target=="source.properties" if name=="source.properties" else
                 target.startswith(NDK_BIN.as_posix()+"/")),"Invalid NDK selected file path")
    return {name:row["sha256"] for name,row in rows.items()}


def managed_chain(summary,evidence,source_sha):
    ndk=ndk_chain(summary)
    pin=summary.get("managed_manifest_sha256")
    if pin is None:
        return "NOT_SUPPLIED", "SAVED_SELECTED_TOOL_RECORD_ONLY" if ndk else "NOT_SUPPLIED"
    name="managed-donor-manifest.json"
    require(valid_pin(pin) and summary["stage_evidence_sha256"][name]==pin,
            "Managed manifest pin mismatch")
    raw=read_regular(evidence/name,1024*1024)
    require(sha(raw)==pin,"Managed manifest bytes changed")
    data=json.loads(raw,object_pairs_hook=unique_keys)
    require(isinstance(data,dict) and set(data) in ({"schema","source_sha","inputs","evidence","xtra_abi","assets"},
                          {"schema","source_sha","inputs","evidence","xtra_abi","assets","environment"})
            and data["schema"]=="galwear-r800-local-donor-manifest-v1" and data["source_sha"]==source_sha,
            "Managed manifest schema or source mismatch")
    rows=data["inputs"]
    require(isinstance(rows,dict) and set(rows)==set(summary["input_sha256"])|{"ndk"},
            "Managed manifest input inventory mismatch")
    for role,row in rows.items():
        fields={"path","tools_sha256"} if role=="ndk" else {"path","sha256"}
        require(isinstance(row,dict) and set(row)==fields,"Managed manifest input fields mismatch")
        if role!="ndk":
            require(row["sha256"]==summary["input_sha256"][role],"Managed manifest input pin mismatch: "+role)
    require(ndk is not None and rows["ndk"]["tools_sha256"]==ndk,"Managed manifest NDK pin mismatch")
    require(type(data["xtra_abi"]) is int and data["xtra_abi"] in (0,1,2) and
            data["xtra_abi"]==summary["xtra_abi"],"Managed manifest XTRA ABI mismatch")
    reports=data["evidence"]
    stock=summary.get("stock_donor_bindings",{})
    pixel=summary.get("pixel_system_binding")
    require(isinstance(reports,dict) and set(reports)=={"system","j4","tizen"} and
            set(stock)=={"j4","tizen"} and isinstance(pixel,dict),"Managed donor reports missing")
    for role,row in reports.items():
        fields={"path","sha256"} if role=="system" else {"path","sha256","archive_sha256"}
        require(isinstance(row,dict) and set(row)==fields,"Managed report fields mismatch")
        observed=pixel if role=="system" else stock[role]
        require(row["sha256"]==observed["report_sha256"],"Managed report pin mismatch: "+role)
        if role!="system":
            require(row["archive_sha256"]==observed["reported_archive_sha256"],
                    "Managed archive pin mismatch: "+role)
    assets=data["assets"]
    if assets is None:
        require(summary.get("assets_manifest_sha256") is None,"Managed asset pin mismatch")
    else:
        require(isinstance(assets,dict) and set(assets)=={"path","sha256"} and
                assets["sha256"]==summary.get("assets_manifest_sha256") and valid_pin(assets["sha256"]),
                "Managed asset pin mismatch")
    # These are saved relative references only, not resolved against the original workspace.
    paths=[row["path"] for row in rows.values()]+[row["path"] for row in reports.values()]
    if assets is not None:
        paths.append(assets["path"])
    if "environment" in data:
        env=data["environment"]
        require(isinstance(env,dict) and set(env)=={"lock","lock_sha256","probe","probe_sha256"} and
                env["lock_sha256"]==summary.get("environment_lock_sha256") and
                env["probe_sha256"]==summary.get("synthetic_mount_probe_sha256") and
                valid_pin(env["lock_sha256"]) and valid_pin(env["probe_sha256"]) and env["lock"]!=env["probe"],
                "Managed manifest environment pins mismatch")
        paths.extend((env["lock"],env["probe"]))
    require(all(isinstance(p,str) and 0<len(p)<=1024 and "\\" not in p and ":" not in p and
                all(x not in ("",".","..") for x in p.split("/")) for p in paths),
            "Invalid managed relative path")
    require(len({row["path"] for row in rows.values()})==len(rows) and
            len({row["path"] for row in reports.values()})==len(reports),"Duplicate managed paths")
    return "SAVED_MANIFEST_CHAIN_ONLY","SAVED_SELECTED_TOOL_PINS_MATCH_MANIFEST"


def base_chain(summary,evidence,source_sha):
    pin=summary.get("base_vendor_identity_sha256")
    managed=summary.get("managed_manifest_sha256") is not None
    if pin is None:
        require(not managed,"Managed build missing base vendor identity evidence")
        return "NOT_SUPPLIED",None
    require(managed,"Unexpected base vendor evidence in unmanaged build")
    name="base-vendor-identity.json"
    require(valid_pin(pin) and summary["stage_evidence_sha256"][name]==pin,
            "Base vendor evidence pin mismatch")
    report=read_report(evidence/name,pin,source_sha,"BASE_VENDOR_IDENTITY_FIELDS_OBSERVED_ONLY")
    status=review_base(report,summary["input_sha256"]["base"],
                       summary["input_sha256"]["effects"],source_sha)
    require(status=="BASE_VENDOR_IDENTITY_FIELDS_OBSERVED_ONLY","Base vendor identity review required")
    return "SAVED_LITERAL_IDENTITY_CHAIN_ONLY",report


def host_chain(summary,evidence,source_sha):
    managed=summary.get("managed_manifest_sha256") is not None
    lock_pin=summary.get("environment_lock_sha256")
    probe_pin=summary.get("synthetic_mount_probe_sha256")
    if lock_pin is None and probe_pin is None:
        require(not managed,"Managed build missing host environment evidence")
        return "NOT_SUPPLIED"
    require(managed and valid_pin(lock_pin) and valid_pin(probe_pin),
            "Unexpected host evidence scope")
    pins=summary["stage_evidence_sha256"]
    require(pins["linux-assembly-lock.json"]==lock_pin and pins["synthetic-mount-probe.json"]==probe_pin,
            "Host evidence inventory pin mismatch")
    _,manifest=read_pinned(evidence/"managed-donor-manifest.json",summary["managed_manifest_sha256"])
    require("environment" in manifest,"Managed manifest missing environment references")
    _,lock=read_pinned(evidence/"linux-assembly-lock.json",lock_pin)
    _,probe=read_pinned(evidence/"synthetic-mount-probe.json",probe_pin)
    return saved_environment(lock,probe,lock_pin,source_sha)


def readiness(root,pin,source_sha,*,capacity_path=None,capacity_pin=None,
              pit_path=None,pit_pin=None,artifacts=None,artifact_pins=None):
    checkout_sha(source_sha)
    root=Path(root).absolute()
    require(root.resolve(strict=True)==root and root.is_dir() and
            {x.name for x in root.iterdir()}=={"development","evidence","local-build-evidence.json"},
            "Expected canonical local build output")
    tree=root/"development"
    evidence=root/"evidence"
    require(all(x.resolve(strict=True)==x and x.is_dir() for x in (tree,evidence)),
            "Canonical build directories required")
    summary=read_report(root/"local-build-evidence.json",pin,source_sha,
                        "LOCAL_GALWEAR_DEVELOPMENT_TREE_BUILT_STATIC_ONLY")
    require(summary.get("schema")=="galwear-r800-local-development-build-v1" and
            all(summary.get(k) is False for k in ("donor_authenticity_verified","full_runtime_built",
                "wear_os_verified","payload_complete","android_handover_tested","hardware_tested")),
            "Unexpected local build scope")
    pins=summary["stage_evidence_sha256"]
    expected=set(STAGES)|RECIPE|stock_inventory(summary)
    if summary.get("managed_manifest_sha256") is not None:
        expected.add("managed-donor-manifest.json")
    if summary.get("environment_lock_sha256") is not None:
        expected.add("linux-assembly-lock.json")
    if summary.get("synthetic_mount_probe_sha256") is not None:
        expected.add("synthetic-mount-probe.json")
    if summary.get("base_vendor_identity_sha256") is not None:
        expected.add("base-vendor-identity.json")
    if summary.get("pixel_system_binding") is not None:
        expected.add("pixel-system-evidence.json")
    if summary.get("assets_manifest_sha256") is not None:
        expected.add("assets-evidence.json")
    require(set(pins)==expected and {x.name for x in evidence.iterdir()}==expected and
            all(valid_pin(h) for h in pins.values()),"Unexpected evidence inventory")
    reports={}
    for name in sorted(expected):
        raw=read_regular(evidence/name,LIMIT)
        require(sha(raw)==pins[name],"Stage report pin mismatch: "+name)
        if name in STAGES:
            reports[name]=read_report(evidence/name,pins[name],source_sha,STAGES[name])
    tree_pin=summary["integrated_evidence_sha256"]
    i=read_report(tree/"integrated-development-evidence.json",tree_pin,source_sha,
                  "FUNCTIONAL_KERNEL_AND_ANDROID_TREE_STAGED_ONLY")
    u=read_report(tree/"development-tree-evidence.json",i["userspace_evidence_sha256"],source_sha,
                  "ANDROID_DEVICE_DEVELOPMENT_TREE_STAGED_ONLY")
    chain(summary,reports,i,u)
    stock_status=stock_chain(summary,evidence,source_sha)
    pixel_status=pixel_chain(summary,evidence,source_sha)
    managed_status,ndk_status=managed_chain(summary,evidence,source_sha)
    base_status,base_identity=base_chain(summary,evidence,source_sha)
    host_status=host_chain(summary,evidence,source_sha)
    baseline=review(tree,tree_pin,source_sha)
    require(baseline==reports["handover-review.json"],"Saved handover differs from recomputed review")
    layout=prepare(tree,tree_pin,source_sha,capacity_path=capacity_path,capacity_pin=capacity_pin)
    recovery=None
    supplied=(pit_path,pit_pin,artifacts,artifact_pins)
    if any(v is not None for v in supplied):
        require(all(v is not None for v in supplied),"Supply all recovery inputs together")
        with tempfile.TemporaryDirectory(prefix="r800-readiness-") as tmp:
            path=Path(tmp)/"layout.json"
            raw=canonical(layout)
            path.write_bytes(raw)
            recovery=review_recovery(tree,tree_pin,path,sha(raw),pit_path,pit_pin,artifacts,
                                     artifact_pins,source_sha,capacity_path=capacity_path,capacity_pin=capacity_pin)
    for name,h in pins.items():
        require(sha(read_regular(evidence/name,LIMIT))==h,"Stage report changed: "+name)
    require(sha(read_regular(root/"local-build-evidence.json",LIMIT))==pin,"Build report changed")
    checkout_sha(source_sha)
    return {"schema":"galwear-r800-development-readiness-v1","status":"HOLD_HARDWARE_UNVERIFIED",
            "source_sha":source_sha,"local_build_evidence_sha256":pin,
            "integrated_evidence_sha256":tree_pin,"stage_evidence_sha256":pins,
            "checks":{"stage_chain":"STATIC_PASS","handover":"STATIC_PASS",
                      "stock_donor_evidence":stock_status,"pixel_system_evidence":pixel_status,
                      "managed_manifest":managed_status,"ndk_selected_tools":ndk_status,
                      "base_vendor_identity":base_status,"host_environment":host_status,
                      "installation_layout":"STATIC_PLAN_ONLY",
                      "recovery_inputs":"OFFLINE_REVIEW_ONLY" if recovery else "NOT_SUPPLIED",
                      "hardware_boot":"NOT_TESTED","wear_os_boot":"NOT_TESTED"},
            "handover":baseline,"installation":layout,"recovery":recovery,
            "stock_donor_bindings":summary.get("stock_donor_bindings",{}),
            "pixel_system_binding":summary.get("pixel_system_binding"),
            "managed_manifest_sha256":summary.get("managed_manifest_sha256"),
            "base_vendor_identity_sha256":summary.get("base_vendor_identity_sha256"),
            "environment_lock_sha256":summary.get("environment_lock_sha256"),
            "synthetic_mount_probe_sha256":summary.get("synthetic_mount_probe_sha256"),
            "base_vendor_identity":base_identity,
            "ndk_selected_tool_evidence":summary.get("ndk_selected_tool_evidence"),
            "original_donor_authenticity_verified":False,"hardware_tested":False,
            "installation_authorized":False,"safe_to_flash":False}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for n in ("build","output","capacity","pit"):
        p.add_argument("--"+n,type=Path,required=n in ("build","output"))
    for n in ("build-sha256","source-sha","capacity-sha256","pit-sha256"):
        p.add_argument("--"+n,required=n in ("build-sha256","source-sha"))
    p.add_argument("--artifact",nargs=3,action="append",metavar=("ROLE","LOCAL_FILE","SHA256"))
    a=p.parse_args()
    if a.artifact is not None:
        require(len(a.artifact)==len(ARTIFACTS) and {n for n,_,_ in a.artifact}==set(ARTIFACTS),
                "Exactly four unique recovery roles required")
    files=None if a.artifact is None else {n:Path(f) for n,f,_ in a.artifact}
    pins=None if a.artifact is None else {n:h for n,_,h in a.artifact}
    repo=Path(__file__).resolve().parents[1]
    require(not any(a.output.resolve().is_relative_to(r) for r in (repo,a.build.resolve())),
            "Report must be outside source and build trees")
    result=readiness(a.build,a.build_sha256,a.source_sha,capacity_path=a.capacity,
                     capacity_pin=a.capacity_sha256,pit_path=a.pit,pit_pin=a.pit_sha256,
                     artifacts=files,artifact_pins=pins)
    with a.output.open("x",encoding="utf-8") as stream:
        json.dump(result,stream,indent=2,sort_keys=True)
        stream.write("\n")
    print(result["status"],"safe_to_flash=false")


if __name__=="__main__":
    main()
