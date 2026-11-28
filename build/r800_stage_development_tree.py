#!/usr/bin/env python3
"""Compose pinned Android and device adaptation layers, without boot or packaging.

The vendor/ tree is retained as build provenance, not a second mounted vendor.
Require the prepared vendor image to contain the exact current overlay bytes.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import tempfile

from r800_android_userspace_preflight import read_regular
from r800_donor_preflight import digest, MAX_DONOR
from r800_extract_ext4 import snapshot_image
from r800_framework_inventory import ext4_member
from r800_graphics_donor_binding import checkout_sha
from r800_extract_super import require
from r800_stage_adaptation_layer import DEVICE, RUNTIME_REQUIRED, MAX_ENTRIES, MAX_TOTAL, MAX_FILE, valid_pin
from r800_stage_android_layer import inspect_pair, metadata
from r800_verify_tizen_stage import unique_keys, guest_name

ANDROID = {"r800dev/android/system.img", "r800-android/vendor.img"}
MANIFEST_LIMIT = 4*1024**2


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def load(root, name, pin, source_sha, android):
    require(valid_pin(pin), "Explicit layer manifest pin required")
    raw = read_regular(root/name, MANIFEST_LIMIT)
    require(sha(raw) == pin, "Layer manifest pin mismatch")
    report = json.loads(raw, object_pairs_hook=unique_keys)
    schema, status, flags = (
        ("galwear-r800-android-layer-v1", "PREPARED_ANDROID_EXT4_PAIR_STAGED_ONLY",
         ("wear_os_verified","donor_authenticity_verified","filesystem_integrity_verified",
          "vendor_compatibility_verified","android_handover_tested","payload_complete",
          "hardware_tested","safe_to_flash")) if android else
        ("galwear-r800-adaptation-layer-v1", "DEVICE_AND_LOCAL_TIZEN_ADAPTATION_STAGED_ONLY",
         ("donor_authenticity_verified","full_runtime_built","complete_vendor_built",
          "payload_complete","android_handover_tested","hardware_tested","safe_to_flash")))
    require(report.get("schema") == schema and report.get("status") == status and
            report.get("source_sha") == source_sha and all(report.get(f) is False for f in flags),
            "Layer scope or source SHA mismatch")
    files = report["files"]
    require(isinstance(files, dict) and 0 < len(files) <= 2*MAX_ENTRIES, "Invalid layer inventory")
    if android:
        require(set(files) == ANDROID, "Unexpected Android image inventory")
    else:
        require(set(DEVICE)|RUNTIME_REQUIRED <= set(files), "Missing adaptation files")
        require(all(valid_pin(report.get(k)) for k in ("device_manifest_sha256","runtime_manifest_sha256")),
                "Missing adaptation provenance pins")
    dirs = set()
    for path,row in files.items():
        require(isinstance(path,str) and len(path)<=1024 and
                all(re.fullmatch(r"[A-Za-z0-9_.@+-]+",p) and p not in (".","..") for p in path.split("/")),
                "Unsafe layer path")
        require(isinstance(row,dict) and type(row.get("bytes")) is int and
                0 < row["bytes"] <= (MAX_DONOR if android else MAX_FILE) and
                valid_pin(row.get("sha256")), "Invalid layer member metadata")
        if android:
            require(row.get("mode")=="0o400", "Unexpected Android image mode")
        elif path in DEVICE:
            require(row.get("layer")=="device" and row.get("mode")==DEVICE[path], "Unexpected device metadata")
        else:
            require(row.get("layer")=="tizen-runtime" and row.get("mode") in ("0o644","0o755"),
                    "Unexpected runtime metadata")
            if path.startswith("r800dev/tzlite/"):
                guest_name(path.removeprefix("r800dev/tzlite"))
            else:
                require(path in RUNTIME_REQUIRED, "Unexpected runtime member")
            if path=="r800dev/gpsbridge" or path.endswith("/ld-linux.so.3") or path.startswith("r800dev/tzlite/usr/bin/"):
                require(row["mode"]=="0o755","Runtime executable mode missing")
        dirs.update(p.as_posix() for p in Path(path).parents if p.as_posix()!=".")
    if not android:
        require(report.get("total_bytes")==sum(r["bytes"] for r in files.values())<=MAX_TOTAL,
                "Invalid adaptation size")
    seen, seen_dirs = set(),set()
    pending=[root]
    while pending:
        with os.scandir(pending.pop()) as entries:
            for entry in entries:
                p=Path(entry.path)
                rel=p.relative_to(root).as_posix()
                s=entry.stat(follow_symlinks=False)
                if stat.S_ISDIR(s.st_mode):
                    require(rel in dirs and not s.st_mode&0o7000,"Unexpected layer directory: "+rel)
                    seen_dirs.add(rel)
                    pending.append(p)
                else:
                    require(stat.S_ISREG(s.st_mode) and s.st_nlink==1 and
                            (rel==name or rel in files),"Unexpected layer entry: "+rel)
                    seen.add(rel)
                    if rel!=name:
                        require(oct(stat.S_IMODE(s.st_mode))==files[rel]["mode"],"Layer mode mismatch: "+rel)
    require(seen==set(files)|{name} and seen_dirs==dirs,"Layer inventory differs from disk")
    return report,raw


def verify_overlay(image, rows, scratch):
    tool=shutil.which("debugfs")
    require(tool,"debugfs required")
    checks={}
    for path,row in sorted(rows.items()):
        if not path.startswith("vendor/"):
            continue
        guest="/"+path.removeprefix("vendor/")
        meta=metadata(tool,image,guest)
        require(meta["type"]=="regular" and oct(meta["mode"])==row["mode"],
                "Vendor overlay member mode/type mismatch: "+guest)
        raw=ext4_member(tool,image,guest,min(MAX_FILE,row["bytes"]),scratch)
        require(raw is not None and len(raw)==row["bytes"] and sha(raw)==row["sha256"],
                "Vendor overlay bytes mismatch: "+guest)
        checks[guest]={"sha256":row["sha256"],"bytes":row["bytes"],"mode":row["mode"]}
    require(set(checks)=={"/"+p.removeprefix("vendor/") for p in DEVICE if p.startswith("vendor/")},
            "Incomplete vendor overlay binding")
    return checks


def assemble(adaptation, adaptation_sha, android, android_sha, output, source_sha):
    checkout_sha(source_sha)
    adaptation,android=Path(adaptation).absolute(),Path(android).absolute()
    require(all(p.resolve(strict=True)==p and p.is_dir() for p in (adaptation,android)),
            "Canonical input layer directories required")
    output=Path(output).absolute()
    repo=Path(__file__).resolve().parents[1]
    require(not output.exists() and not output.is_symlink() and
            not any(output.resolve().is_relative_to(p) for p in (adaptation,android,repo)),
            "Fresh output outside input trees required")
    inputs=[(adaptation,"adaptation-layer-evidence.json",adaptation_sha,False),
            (android,"android-layer-evidence.json",android_sha,True)]
    loaded=[load(root,name,pin,source_sha,kind) for root,name,pin,kind in inputs]
    a,b=(item[0] for item in loaded)
    require(not set(a["files"])&set(b["files"]),"Layer paths collide")
    with tempfile.TemporaryDirectory(dir=output.parent,prefix="r800-development-") as tmp:
        work=Path(tmp)
        tree=work/"tree"
        tree.mkdir()
        rows={}
        for (root,_,_,kind),(report,_) in zip(inputs,loaded):
            for path,row in sorted(report["files"].items()):
                dest=tree/path
                dest.parent.mkdir(parents=True,exist_ok=True)
                if kind:
                    snapshot_image(root/path,dest,row["sha256"])
                    require(digest(dest,MAX_DONOR)=={"bytes":row["bytes"],"sha256":row["sha256"]},
                            "Staged Android image size or digest mismatch")
                else:
                    data=read_regular(root/path,MAX_FILE)
                    require(len(data)==row["bytes"] and sha(data)==row["sha256"],"Adaptation bytes changed: "+path)
                    with dest.open("xb") as stream:
                        stream.write(data)
                    dest.chmod(int(row["mode"],8))
                rows[path]={**{k:row[k] for k in ("bytes","sha256","mode")},
                            "layer":"android" if kind else row["layer"]}
        sysimg=tree/"r800dev/android/system.img"
        venimg=tree/"r800-android/vendor.img"
        inspection=inspect_pair(sysimg,venimg,work)
        overlay=verify_overlay(venimg,rows,work)
        for module in ("audio.primary.r800.so","gps.r800.so","hwcomposer.r800.so","sensors.r800.so"):
            require(rows["vendor/lib/hw/"+module]["sha256"]==rows["r800dev/hwc/"+module]["sha256"],
                    "HAL copies differ: "+module)
        require(rows["r800dev/bin/wpcd"]["sha256"]==rows["r800dev/charger/wpcd"]["sha256"],"WPCD copies differ")
        for path,row in rows.items():
            require(digest(tree/path,MAX_DONOR if path in ANDROID else MAX_FILE)==
                    {"bytes":row["bytes"],"sha256":row["sha256"]},"Staged file changed: "+path)
            require(oct(stat.S_IMODE((tree/path).stat().st_mode))==row["mode"],"Staged mode changed")
        for (root,name,pin,kind),(report,raw) in zip(inputs,loaded):
            require(load(root,name,pin,source_sha,kind)[1]==raw,"Layer manifest changed")
            for path,row in report["files"].items():
                require(digest(root/path,MAX_DONOR if kind else MAX_FILE)==
                        {"bytes":row["bytes"],"sha256":row["sha256"]},"Input layer changed: "+path)
        checkout_sha(source_sha)
        result={"schema":"galwear-r800-development-tree-v1",
                "status":"ANDROID_DEVICE_DEVELOPMENT_TREE_STAGED_ONLY",
                "source_sha":source_sha,"adaptation_manifest_sha256":adaptation_sha,
                "android_manifest_sha256":android_sha,"files":rows,
                "total_bytes":sum(r["bytes"] for r in rows.values()),
                "android_inspection":inspection,"vendor_overlay_matches":overlay,
                "vendor_tree_role":"BUILD_PROVENANCE_ONLY",
                "missing_inputs_and_gates":["Tizen configuration/plugins and ownership",
                    "Display assets, kernel/DTB handover and partition capacity",
                    "Wear OS provenance, VINTF/SELinux/APEX/ART compatibility",
                    "Hardware boot, recovery and installation acceptance"],
                "wear_os_verified":False,"donor_authenticity_verified":False,
                "vendor_compatibility_verified":False,"payload_complete":False,
                "android_handover_tested":False,"hardware_tested":False,"safe_to_flash":False}
        (tree/"development-tree-evidence.json").write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
        require(not output.exists() and not output.is_symlink(),"Output already exists")
        os.rename(tree,output)
    return result


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ("adaptation","android","output"):
        p.add_argument("--"+name,type=Path,required=True)
    for name in ("adaptation-sha256","android-sha256","source-sha"):
        p.add_argument("--"+name,required=True)
    a=p.parse_args()
    report=assemble(a.adaptation,a.adaptation_sha256,a.android,a.android_sha256,a.output,a.source_sha)
    print(report["status"],len(report["files"]),"files; safe_to_flash=false")


if __name__=="__main__":
    main()
