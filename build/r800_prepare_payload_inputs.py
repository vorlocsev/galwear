#!/usr/bin/env python3
"""Stage reviewed compiled components and local assets, not a flashable payload."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tempfile

from r800_android_userspace_preflight import read_regular
from r800_donor_preflight import verify_components, checked
from r800_payload_candidate import ASSET_SIZES, HALS, BINS, RADIO_FILES, CHARGER_TOOLS
from r800_stage_components import TOOLS, static_arm, dex
from r800_vendor_inputs import file_info

COMPILED = set(TOOLS) | {"bin/" + n for n in BINS} | {
    "hwc/" + n for n in HALS} | {
    "keepwifi.dex", "fw/bt/libbt-vendor.so", "fw/bt/bt_vendor.conf"}
RADIO = set(RADIO_FILES) - {"fw/bt/libbt-vendor.so", "fw/bt/bt_vendor.conf"}
MAX_FILE = 64*1024**2


def manifest(root, name):
    return json.loads(read_regular(checked(root,name),1024*1024))


def match(raw, expected, name):
    if (len(raw) != expected["bytes"] or
            hashlib.sha256(raw).hexdigest() != expected["sha256"]):
        raise ValueError("Input hash or size mismatch: " + name)


def prepare(components, assets, radio, output, source_sha):
    if not re.fullmatch(r"[0-9a-f]{40}", source_sha):
        raise ValueError("Expected exact source SHA")
    components, assets, radio = [Path(p).resolve(strict=True) for p in (components,assets,radio)]
    output = Path(output).absolute()
    if output.exists() or output.is_symlink():
        raise ValueError("Output already exists")
    if any(output.resolve().is_relative_to(p) for p in (components,assets,radio)):
        raise ValueError("Output inside input tree")
    verify_components(components,source_sha)
    cm = manifest(components,"component-evidence.json")["files"]
    am = manifest(assets,"assets-evidence.json")
    rm = manifest(radio,"ext4-evidence.json")
    if set(am) != set(ASSET_SIZES):
        raise ValueError("Asset inventory mismatch")
    if (rm.get("profile") != "tizen" or rm.get("safe_to_flash") is not False
            or not re.fullmatch(r"[0-9a-f]{64}",rm.get("image_sha256",""))):
        raise ValueError("Expected Tizen radio extraction evidence")
    if not COMPILED <= {n.removeprefix("payload/") for n in cm if n.startswith("payload/")}:
        raise ValueError("Compiled payload inventory incomplete")
    with tempfile.TemporaryDirectory(dir=output.parent) as tmp:
        tree = Path(tmp)/"stage"
        tree.mkdir()
        files = {}
        def add(root, source, dest, evidence, origin, mode):
            raw = read_regular(checked(root,source),MAX_FILE)
            match(raw,evidence,dest)
            if dest.startswith("bin/") or dest in CHARGER_TOOLS:
                static_arm(raw)
            elif dest == "keepwifi.dex":
                dex(raw)
            elif dest.endswith(".so"):
                file_info(checked(root,source),True)
            if dest in ASSET_SIZES and len(raw)!=ASSET_SIZES[dest]:
                raise ValueError("Wrong asset dimensions: "+dest)
            target = tree/dest
            target.parent.mkdir(parents=True,exist_ok=True)
            with target.open("xb") as stream:
                stream.write(raw)
            target.chmod(mode)
            files[dest] = {"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest(),
                           "mode":oct(mode),"origin":origin,"source":source}
        for name in sorted(COMPILED):
            key = "payload/"+name
            mode = 0o755 if name.startswith("bin/") or name in CHARGER_TOOLS else 0o644
            add(components,key,name,cm[key],"compiled:"+source_sha,mode)
        for name in sorted(ASSET_SIZES):
            add(assets,name,name,am[name],"local_asset_conversion",0o644)
        for name in sorted(RADIO):
            key = "payload/"+name
            evidence = rm["files"].get(key,{})
            if evidence.get("status")!="EXTRACTED":
                raise ValueError("Missing verified radio extraction: "+name)
            add(radio,key,name,evidence,"tizen_image:"+rm["image_sha256"],0o644)
        if (tree/"bin/wpcd").read_bytes() != (tree/"charger/wpcd").read_bytes():
            raise ValueError("WPCD copies differ")
        report = {"status":"PARTIAL_PAYLOAD_INPUTS_ONLY","source_sha":source_sha,
                  "files":files,"missing":["Android system image","Tizen configuration and plugins",
                  "linked GPSBridge","remaining peripheral firmware","independent acceptance gates"],
                  "donor_authenticity_verified":False,"runtime_verified":False,
                  "payload_complete":False,"safe_to_flash":False}
        (tree/"payload-inputs-evidence.json").write_text(json.dumps(report,indent=2,sort_keys=True))
        os.rename(tree,output)
    return report


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for arg in ("components","assets","radio","output"):
        p.add_argument("--"+arg,type=Path,required=True)
    p.add_argument("--source-sha",required=True)
    a=p.parse_args()
    print(json.dumps(prepare(a.components,a.assets,a.radio,a.output,a.source_sha),sort_keys=True))


if __name__=="__main__":
    main()
