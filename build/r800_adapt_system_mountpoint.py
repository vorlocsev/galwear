#!/usr/bin/env python3
"""Rootless, minimal adaptation of an existing Android 11 system-as-root EXT4.

Only add the missing /oem mountpoint to a private copy. Do not convert a flat
system partition, merge product/system_ext, remove AVB data, alter Android
properties or patch ART/APEX. A successful result is not boot acceptance.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

from r800_extract_ext4 import snapshot_image, command
from r800_framework_inventory import ext4_member
from r800_stage_android_layer import SYSTEM_DIRS, SYSTEM_FILES, metadata, directory, elf_header, MAX_MEMBER, MAX_TOTAL
from r800_partition_identity import filesystem, literal_properties, property_inventory
from r800_donor_preflight import digest, MAX_DONOR
from r800_graphics_donor_binding import checkout_sha
from r800_extract_super import require


def inspect_system(tool, image, scratch):
    members={path:directory(tool,image,path) for path in SYSTEM_DIRS if path!="/oem"}
    init=metadata(tool,image,"/init")
    files=SYSTEM_FILES
    if init["type"]=="symlink":
        link=re.search(r'Fast link dest:\s*"([^"]+)"',init["stat"])
        require(link and link[1] in ("/system/bin/init","system/bin/init"),"Unexpected Android init symlink")
        members["/init"]={"type":"symlink","target":link[1]}
        files+=("/system/bin/init",)
    else:
        files+=("/init",)
    total=0
    for path in files:
        row=metadata(tool,image,path)
        require(row["type"]=="regular" and row["mode"]&0o111,"Expected executable Android member: "+path)
        raw=ext4_member(tool,image,path,min(MAX_MEMBER,MAX_TOTAL-total),scratch)
        require(raw is not None,"Missing Android executable: "+path)
        total+=len(raw)
        members[path]={"type":"regular","mode":oct(row["mode"]),"bytes":len(raw),
                       "sha256":hashlib.sha256(raw).hexdigest(),
                       **elf_header(raw,path,True,path.endswith("app_process32"))}
    for path in ("/system/build.prop","/system/etc/prop.default"):
        raw=ext4_member(tool,image,path,min(1024*1024,MAX_TOTAL-total),scratch)
        require(raw is not None,"Missing Android property file: "+path)
        total+=len(raw)
        members[path]={"sha256":hashlib.sha256(raw).hexdigest(),"bytes":len(raw)}
        if path.endswith("/build.prop"):
            props=property_inventory(literal_properties(raw,path))
            require(props["literal_android_11_hint"] and props["literal_arm32_hint"],
                    "Expected Android 11 system with ARM32 ABI")
    return members


def check_fs(tool,image):
    result=subprocess.run([tool,"-fn",str(image)],env={**os.environ,"LC_ALL":"C"},
                          capture_output=True,text=True,timeout=300)
    require(result.returncode==0,"Read-only e2fsck did not pass; refuse repair or journal replay")


def oem_info(tool,image):
    result=command(tool,image,"stat /oem")
    if "File not found" in result.stderr:
        return None
    row=metadata(tool,image,"/oem")
    require(row["type"]=="directory","Existing /oem is not a directory")
    return {"type":"directory","mode":oct(row["mode"])}


def prepare(image, image_sha, output, source_sha):
    checkout_sha(source_sha)
    require(re.fullmatch(r"[0-9a-f]{64}",image_sha),"Explicit input SHA-256 required")
    image=Path(image).absolute()
    output=Path(output).absolute()
    repo=Path(__file__).resolve().parents[1]
    require(image.resolve(strict=True)==image,"Canonical donor image required")
    require(not output.exists() and not output.is_symlink() and
            not output.resolve().is_relative_to(repo),"Fresh output outside checkout required")
    debugfs,e2fsck=shutil.which("debugfs"),shutil.which("e2fsck")
    require(debugfs and e2fsck,"debugfs and e2fsck required")
    with tempfile.TemporaryDirectory(dir=output.parent,prefix="r800-system-adapt-") as tmp:
        work=Path(tmp)
        stage=work/"result"
        stage.mkdir()
        target=stage/"system.img"
        snapshot_image(image,target,image_sha)
        original=digest(target,MAX_DONOR)
        fs=filesystem(target)
        require(fs["kind"]=="EXT4","Raw EXT4 system-as-root required; no EROFS conversion")
        check_fs(e2fsck,target)
        before=inspect_system(debugfs,target,work)
        oem=oem_info(debugfs,target)
        added=oem is None
        if added:
            require(fs["filesystem_bytes"]==fs["partition_bytes"],
                    "Trailing partition data present; refuse modification (possible AVB/footer)")
            target.chmod(0o600)
            result=subprocess.run([debugfs,"-w","-R","mkdir /oem",str(target)],
                env={**os.environ,"LC_ALL":"C"},capture_output=True,text=True,timeout=60,check=True)
            require(result.stdout.strip()=="" and all(line.startswith("debugfs ")
                    for line in result.stderr.splitlines() if line.strip()),"debugfs mkdir reported unexpected output")
            row=metadata(debugfs,target,"/oem")
            require(row["type"]=="directory" and row["mode"]==0o755 and
                    re.search(r"User:\s+0\s+Group:\s+0\b",row["stat"]),
                    "New /oem metadata differs from root:root 0755")
            target.chmod(0o400)
        check_fs(e2fsck,target)
        after=inspect_system(debugfs,target,work)
        require(after==before,"Selected original system files or directories changed")
        final_oem=oem_info(debugfs,target)
        require(final_oem is not None,"Required /oem mountpoint missing")
        require(filesystem(target)==fs,"System image geometry changed")
        final=digest(target,MAX_DONOR)
        require(final["bytes"]==original["bytes"] and (added or final==original),
                "Unexpected system image change")
        require(digest(image,MAX_DONOR)==original,"Original donor changed")
        checkout_sha(source_sha)
        report={"schema":"galwear-r800-system-mountpoint-adaptation-v1",
                "status":"SYSTEM_AS_ROOT_MOUNTPOINT_PREPARED_ONLY","source_sha":source_sha,
                "original":original,"system":final,"filesystem":fs,
                "oem_mountpoint":final_oem,"added_oem":added,
                "selected_system_members":after,"e2fsck_read_only_pass":True,
                "selected_original_members_unchanged":True,
                "all_original_members_verified":False,"selinux_label_compatibility_verified":False,
                "avb_verified":False,"wear_os_verified":False,"android_handover_tested":False,
                "hardware_tested":False,"safe_to_flash":False}
        (stage/"system-adaptation-evidence.json").write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
        require(not output.exists() and not output.is_symlink(),"Output already exists")
        os.rename(stage,output)
    return report


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--image",type=Path,required=True)
    p.add_argument("--image-sha256",required=True)
    p.add_argument("--output",type=Path,required=True)
    p.add_argument("--source-sha",required=True)
    a=p.parse_args()
    result=prepare(a.image,a.image_sha256,a.output,a.source_sha)
    print(result["status"],"added_oem="+str(result["added_oem"]).lower(),"safe_to_flash=false")


if __name__=="__main__":
    main()
