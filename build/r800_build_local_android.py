#!/usr/bin/env python3
"""Build a local Android layer from explicitly pinned original donor files.

No downloads, installation, guest execution or hardware access. The vendor
recipe requires a trusted local Linux environment with root and unshare.
All intermediate images stay private; only the staged pair and evidence
are published. This is not a complete Wear OS firmware.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import tempfile

from r800_adapt_system_mountpoint import prepare
from r800_build_local_vendor import build as build_vendor
from r800_stage_android_layer import stage
from r800_stage_development_tree import verify_overlay
from r800_donor_preflight import digest, verify_components, MAX_DONOR
from r800_android_userspace_preflight import read_regular
from r800_stage_adaptation_layer import valid_pin
from r800_graphics_donor_binding import checkout_sha
from r800_extract_super import require
from r800_verify_tizen_stage import unique_keys

MAX_FILE=64*1024**2
REPORT_LIMIT=16*1024**2


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def evidence(path, report):
    raw=read_regular(path,REPORT_LIMIT)
    require(json.loads(raw,object_pairs_hook=unique_keys)==report,
            "On-disk intermediate evidence mismatch: "+path.name)
    return sha(raw)


def scope(report, source_sha, status):
    require(report.get("source_sha")==source_sha and
            report.get("status")==status and report.get("safe_to_flash") is False,
            "Intermediate source or scope mismatch: "+status)


def build(components, system, system_sha, base, base_sha, j4, j4_sha,
          effects, effects_sha, output, source_sha):
    checkout_sha(source_sha)
    repo=Path(__file__).resolve().parents[1]
    components,system,base,j4,effects=(Path(p).absolute() for p in (components,system,base,j4,effects))
    require(all(p.resolve(strict=True)==p for p in (components,system,base,j4,effects)),
            "Canonical local inputs required")
    require(all(valid_pin(p) for p in (system_sha,base_sha,j4_sha,effects_sha)) and
            len({system_sha,base_sha,j4_sha})==3,"Explicit distinct image pins required")
    output=Path(output).absolute()
    require(not output.exists() and not output.is_symlink() and
            not any(output.resolve().is_relative_to(p) for p in (repo,components)),
            "Fresh output outside input trees required")
    verify_components(components,source_sha)
    component_raw=read_regular(components/"component-evidence.json",1024*1024)
    component_pin=sha(component_raw)
    donors=((system,system_sha,MAX_DONOR),(base,base_sha,MAX_DONOR),
            (j4,j4_sha,MAX_DONOR),(effects,effects_sha,MAX_FILE))
    for path,pin,limit in donors:
        require(digest(path,limit)["sha256"]==pin,"Original donor pin mismatch: "+path.name)
    with tempfile.TemporaryDirectory(dir=output.parent,prefix="r800-android-build-") as tmp:
        work=Path(tmp)
        adapted=work/"adapted"
        vendor=work/"vendor"
        layer=work/"android"
        s=prepare(system,system_sha,adapted,source_sha)
        scope(s,source_sha,"SYSTEM_AS_ROOT_MOUNTPOINT_PREPARED_ONLY")
        require(s["original"]["sha256"]==system_sha and s["selected_original_members_unchanged"] is True,
                "Unexpected system adaptation provenance")
        system_pin=s["system"]["sha256"]
        require(valid_pin(system_pin) and digest(adapted/"system.img",MAX_DONOR)==s["system"],
                "Adapted system image digest mismatch")
        s_pin=evidence(adapted/"system-adaptation-evidence.json",s)
        v=build_vendor(components,base,base_sha,j4,j4_sha,effects,effects_sha,
                       adapted/"system.img",system_pin,vendor,source_sha)
        scope(v,source_sha,"LOCAL_VENDOR_CANDIDATE_OVERLAY_MATCH_ONLY")
        require(v["component_manifest_sha256"]==component_pin and
                v["donor_sha256"]=={"base":base_sha,"j4":j4_sha,"effects":effects_sha,"system":system_pin},
                "Vendor recipe used different inputs")
        vendor_pin=v["vendor"]["sha256"]
        require(valid_pin(vendor_pin) and digest(vendor/"vendor.img",MAX_DONOR)==v["vendor"],
                "Vendor output digest mismatch")
        v_pin=evidence(vendor/"vendor-build-evidence.json",v)
        a=stage(adapted/"system.img",system_pin,vendor/"vendor.img",vendor_pin,layer,source_sha)
        scope(a,source_sha,"PREPARED_ANDROID_EXT4_PAIR_STAGED_ONLY")
        require(a["files"]=={
            "r800dev/android/system.img":{**s["system"],"mode":"0o400"},
            "r800-android/vendor.img":{**v["vendor"],"mode":"0o400"}},
            "Android layer image identity mismatch")
        a_pin=evidence(layer/"android-layer-evidence.json",a)
        # Recheck the final vendor image directly against the original
        # component manifest rather than relying solely on vendor metadata.
        from r800_vendor_inputs import OVERLAY
        from r800_compiled_overlay_ext4 import destination
        compiled=json.loads(component_raw,object_pairs_hook=unique_keys)["files"]
        rows={"vendor/"+destination(n):{**compiled["vendor-overlay/"+n],"mode":"0o644"}
              for n in OVERLAY}
        matches=verify_overlay(layer/"r800-android/vendor.img",rows,work)
        require(matches==v["overlay_matches"],"Final vendor overlay differs from recipe result")
        for path,row in a["files"].items():
            require(digest(layer/path,MAX_DONOR)=={"bytes":row["bytes"],"sha256":row["sha256"]},
                    "Final Android image changed")
        verify_components(components,source_sha)
        require(read_regular(components/"component-evidence.json",1024*1024)==component_raw,
                "Component manifest changed")
        for path,pin,limit in donors:
            require(digest(path,limit)["sha256"]==pin,"Original donor changed: "+path.name)
        require(evidence(adapted/"system-adaptation-evidence.json",s)==s_pin and
                evidence(vendor/"vendor-build-evidence.json",v)==v_pin and
                evidence(layer/"android-layer-evidence.json",a)==a_pin,
                "Intermediate evidence changed")
        result={"schema":"galwear-r800-local-android-build-v1",
                "status":"LOCAL_ANDROID_LAYER_BUILT_STATIC_ONLY","source_sha":source_sha,
                "component_manifest_sha256":component_pin,
                "original_donor_sha256":{"system":system_sha,"base":base_sha,
                                         "j4":j4_sha,"effects":effects_sha},
                "system_adaptation_evidence_sha256":s_pin,
                "vendor_build_evidence_sha256":v_pin,
                "android_layer_evidence_sha256":a_pin,
                "files":a["files"],"overlay_matches":matches,
                "donor_authenticity_verified":False,"wear_os_verified":False,
                "selinux_compatibility_verified":False,"vendor_compatibility_verified":False,
                "android_handover_tested":False,"payload_complete":False,
                "hardware_tested":False,"safe_to_flash":False}
        # Preserve the exact Android Layer inventory for the integrated
        # assembler. All build provenance is a sibling, not an extra layer file.
        reports=work/"evidence"
        reports.mkdir()
        for src in (adapted/"system-adaptation-evidence.json",vendor/"vendor-build-evidence.json"):
            (reports/src.name).write_bytes(read_regular(src,REPORT_LIMIT))
        for name,pin in v["recipe_evidence_sha256"].items():
            require(name in ("input-evidence.json","recipe-preflight.json","merged-vendor-graph.json"),
                    "Unexpected recipe report name")
            raw=read_regular(vendor/name,REPORT_LIMIT)
            require(sha(raw)==pin,"Recipe evidence pin mismatch")
            (reports/name).write_bytes(raw)
        (work/"android-build-evidence.json").write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
        publish=work/"result"
        publish.mkdir()
        for name in ("android","evidence","android-build-evidence.json"):
            os.rename(work/name,publish/name)
        checkout_sha(source_sha)
        require(not output.exists() and not output.is_symlink(),"Output already exists")
        os.rename(publish,output)
    return result


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ("components","system","base","j4","effects","output"):
        p.add_argument("--"+name,type=Path,required=True)
    for name in ("system-sha256","base-sha256","j4-sha256","effects-sha256","source-sha"):
        p.add_argument("--"+name,required=True)
    a=p.parse_args()
    report=build(a.components,a.system,a.system_sha256,a.base,a.base_sha256,
                 a.j4,a.j4_sha256,a.effects,a.effects_sha256,a.output,a.source_sha)
    print(report["status"],"safe_to_flash=false")


if __name__=="__main__":
    main()
