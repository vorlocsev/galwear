#!/usr/bin/env python3
"""Feed same-head compiled HALs into the historical local vendor build.

The overlay-only command is rootless. Actual donor assembly requires root
and a private mount namespace; never mount original images or use a watch.
No installation package or runtime compatibility claim is made.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

from r800_android_userspace_preflight import read_regular
from r800_donor_preflight import verify_components, digest, MAX_DONOR
from r800_extract_ext4 import snapshot_image
from r800_vendor_inputs import OVERLAY, file_info
from r800_compiled_overlay_ext4 import destination
from r800_stage_development_tree import verify_overlay
from r800_stage_adaptation_layer import valid_pin
from r800_graphics_donor_binding import checkout_sha
from r800_extract_super import require
from r800_verify_tizen_stage import unique_keys

MAX_FILE=64*1024**2
REPORT="vendor-input-evidence.json"


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def stage_overlay(components, output, source_sha):
    checkout_sha(source_sha)
    components=Path(components).absolute()
    output=Path(output).absolute()
    repo=Path(__file__).resolve().parents[1]
    require(components.resolve(strict=True)==components and components.is_dir(),
            "Canonical compiled component directory required")
    require(not output.exists() and not output.is_symlink() and
            not any(output.resolve().is_relative_to(p) for p in (components,repo)),
            "Fresh output outside input trees required")
    verify_components(components,source_sha)
    manifest=read_regular(components/"component-evidence.json",1024*1024)
    rows=json.loads(manifest,object_pairs_hook=unique_keys)["files"]
    with tempfile.TemporaryDirectory(dir=output.parent,prefix="r800-vendor-overlay-") as tmp:
        tree=Path(tmp)/"tree"
        tree.mkdir()
        overlay=tree/"overlay"
        overlay.mkdir()
        files={}
        for name in sorted(OVERLAY):
            path="vendor-overlay/"+name
            raw=read_regular(components/path,MAX_FILE)
            row=rows[path]
            require(row["bytes"]==len(raw) and row["sha256"]==sha(raw) and row["mode"]=="0o644",
                    "Compiled overlay member changed: "+name)
            dest=overlay/name
            dest.parent.mkdir(parents=True,exist_ok=True)
            with dest.open("xb") as stream:
                stream.write(raw)
            dest.chmod(0o644)
            files[name]=file_info(dest,name.endswith(".so"))
            require(files[name]["sha256"]==row["sha256"],"Staged overlay mismatch")
        verify_components(components,source_sha)
        require(read_regular(components/"component-evidence.json",1024*1024)==manifest,
                "Component manifest changed")
        checkout_sha(source_sha)
        report={"schema":"galwear-r800-vendor-input-v1",
                "status":"SAME_HEAD_VENDOR_OVERLAY_STAGED_ONLY",
                "source_sha":source_sha,"component_manifest_sha256":sha(manifest),
                "files":files,"donor_images_used":False,"vendor_image_built":False,
                "hal_runtime_verified":False,"safe_to_flash":False}
        (tree/REPORT).write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
        require(not output.exists() and not output.is_symlink(),"Output already exists")
        os.rename(tree,output)
    return report


def build(components, base, base_sha, j4, j4_sha, effects, effects_sha,
          system, system_sha, output, source_sha):
    checkout_sha(source_sha)
    require(os.geteuid()==0 and shutil.which("unshare"),
            "Local root build and unshare required")
    require(all(valid_pin(p) for p in (base_sha,j4_sha,effects_sha,system_sha)) and base_sha!=j4_sha,
            "Explicit distinct vendor donor pins and system/effects pins required")
    repo=Path(__file__).resolve().parents[1]
    components,base,j4,effects,system=(Path(p).absolute() for p in (components,base,j4,effects,system))
    require(all(p.resolve(strict=True)==p for p in (components,base,j4,effects,system)),
            "Canonical local inputs required")
    output=Path(output).absolute()
    require(not output.exists() and not output.is_symlink() and
            not any(output.resolve().is_relative_to(p) for p in (repo,components)),
            "Fresh output outside input trees required")
    with tempfile.TemporaryDirectory(dir=output.parent,prefix="r800-vendor-local-") as tmp:
        work=Path(tmp)
        stage=work/"result"
        stage.mkdir()
        overlay=work/"prepared"
        report=stage_overlay(components,overlay,source_sha)
        sources=((base,base_sha,"base.img"),(j4,j4_sha,"j4.img"),(system,system_sha,"system.img"))
        for path,pin,name in sources:
            snapshot_image(path,work/name,pin)
        raw=read_regular(effects,MAX_FILE)
        require(sha(raw)==effects_sha,"Effects library pin mismatch")
        (work/"effects.so").write_bytes(raw)
        (work/"effects.so").chmod(0o400)
        file_info(work/"effects.so",True)
        env={**os.environ,"LC_ALL":"C","R800_SYSTEM_IMAGE":str(work/"system.img"),
             "R800_SYSTEM_SHA256":system_sha}
        for name in ("R800_LINKER_CONFIG","R800_LINKER_CONFIG_SHA256","BASH_ENV","ENV",
                     "LD_PRELOAD","LD_LIBRARY_PATH","LD_AUDIT"):
            env.pop(name,None)
        subprocess.run(["unshare","--mount","--propagation","private","bash",
                        str(repo/"build/build_vendor.sh"),str(work/"base.img"),str(work/"j4.img"),
                        str(overlay/"overlay"),str(work/"effects.so"),str(work/"recipe")],
                       env=env,check=True)
        candidate=work/"recipe/vendor.candidate.img"
        rows={"vendor/"+destination(n):{**r,"mode":"0o644"} for n,r in report["files"].items()}
        checked=verify_overlay(candidate,rows,work)
        result_image=stage/"vendor.img"
        observed=digest(candidate,MAX_DONOR)
        snapshot_image(candidate,result_image,observed["sha256"])
        require(verify_overlay(result_image,rows,work)==checked,"Copied vendor overlay differs")
        for path,pin,name in sources:
            require(digest(path,MAX_DONOR)["sha256"]==pin and digest(work/name,MAX_DONOR)["sha256"]==pin,
                    "Vendor or system donor changed")
        require(sha(read_regular(effects,MAX_FILE))==effects_sha,"Effects donor changed")
        verify_components(components,source_sha)
        require(sha(read_regular(components/"component-evidence.json",1024*1024))==
                report["component_manifest_sha256"],"Component manifest changed")
        evidence={}
        for name in ("input-evidence.json","recipe-preflight.json","merged-vendor-graph.json"):
            data=read_regular(work/"recipe"/name,16*1024**2)
            (stage/name).write_bytes(data)
            evidence[name]=sha(data)
        checkout_sha(source_sha)
        result={"schema":"galwear-r800-local-vendor-build-v1",
                "status":"LOCAL_VENDOR_CANDIDATE_OVERLAY_MATCH_ONLY","source_sha":source_sha,
                "component_manifest_sha256":report["component_manifest_sha256"],
                "donor_sha256":{"base":base_sha,"j4":j4_sha,"system":system_sha,"effects":effects_sha},
                "vendor":observed,"overlay_matches":checked,"recipe_evidence_sha256":evidence,
                "donor_authenticity_verified":False,"selinux_compatibility_verified":False,
                "vendor_compatibility_verified":False,"hal_runtime_verified":False,
                "hardware_tested":False,"safe_to_flash":False}
        (stage/"vendor-build-evidence.json").write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
        require(not output.exists() and not output.is_symlink(),"Output already exists")
        os.rename(stage,output)
    return result


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("mode",choices=("overlay","build"))
    p.add_argument("--components",required=True,type=Path)
    p.add_argument("--output",required=True,type=Path)
    p.add_argument("--source-sha",required=True)
    for name in ("base","j4","effects","system"):
        p.add_argument("--"+name,type=Path)
        p.add_argument("--"+name+"-sha256")
    a=p.parse_args()
    if a.mode=="overlay":
        result=stage_overlay(a.components,a.output,a.source_sha)
    else:
        require(all(getattr(a,n) is not None and getattr(a,n+"_sha256") is not None
                    for n in ("base","j4","effects","system")),"All four local donors and pins required")
        result=build(a.components,a.base,a.base_sha256,a.j4,a.j4_sha256,a.effects,a.effects_sha256,
                     a.system,a.system_sha256,a.output,a.source_sha)
    print(result["status"],"safe_to_flash=false")


if __name__=="__main__":
    main()
