#!/usr/bin/env python3
"""Read selected ARM32 Bionic/ART from pinned Wear OS 5.1 System.

No guest execution, mounts, APEX activation, signature or boot claim.
"""
import hashlib
from pathlib import Path
import shutil
import subprocess
import tempfile
import zipfile

from r800_art_apex_mapping import ApexReader
from r800_extract_ext4 import snapshot_image
from r800_framework_inventory import ext4_member, classify, MAX_MEMBER
from r800_android_runtime_extract import MAX_APEX
from r800_arm32_runtime_extract import extract
from r800_graphics_donor_binding import checkout_sha
from r800_donor_preflight import digest

SYSTEM_PIN="aa1c723879307985c3c86f79fdc4e9a352f4b0e4d2c45be4c83d9972dbcaaaa3"
MODULES={
    "com.android.runtime":("/system/apex/com.android.runtime.apex",
        ("/bin/linker","/bin/linker64","/lib/bionic/libc.so","/lib/bionic/libm.so",
         "/lib/bionic/libdl.so","/lib/bionic/libdl_android.so","/lib/bionic/ld-android.so")),
    "com.android.art":("/system/apex/com.google.android.art.apex",
        ("/bin/dex2oat32","/bin/dex2oat64","/bin/dex2oat","/lib/libart.so",
         "/lib/libartbase.so","/javalib/core-oj.jar","/javalib/core-libart.jar")),
}
REQUIRED_RUNTIME=("/bin/linker","/lib/bionic/libc.so","/lib/bionic/libm.so","/lib/bionic/libdl.so")
ERRORS=(OSError,ValueError,RuntimeError,KeyError,zipfile.BadZipFile,subprocess.SubprocessError)


def audit(image,pin,source,output):
    if pin != SYSTEM_PIN:
        raise ValueError("Expected observed Wear OS 5.1 System SHA-256")
    checkout_sha(source)
    image,output=Path(image),Path(output)
    if output.exists() or output.is_symlink():
        raise ValueError("Fresh runtime output required")
    tool=shutil.which("debugfs")
    if not tool:
        raise ValueError("debugfs required")
    modules={}
    with tempfile.TemporaryDirectory(prefix="wear51-apex-",dir=output.parent) as tmp:
        scratch=Path(tmp)
        private=scratch/"system.img"
        snapshot_image(image,private,pin)
        for module,(path,paths) in MODULES.items():
            row={"status":"REVIEW_REQUIRED","members":{}}
            modules[module]=row
            try:
                raw=ext4_member(tool,private,path,MAX_APEX,scratch)
                if raw is None:
                    raise ValueError("Expected observed APEX package")
                row["package_sha256"]=hashlib.sha256(raw).hexdigest()
                row["package_bytes"]=len(raw)
                del raw
                directory=scratch/module
                directory.mkdir()
                def read_partition(requested,limit):
                    if requested!=path:
                        raise ValueError("Unexpected APEX path")
                    return ext4_member(tool,private,path,limit,directory)
                reader=ApexReader([(module,path,row["package_sha256"])],read_partition,directory)
                apex_tool,payload,workspace,*_=reader.open(module)
                row["package"]=reader.evidence[module]
                for member in paths:
                    try:
                        data=ext4_member(apex_tool,payload,member,MAX_MEMBER,workspace)
                        row["members"][member]=({"status":"NOT_FOUND"} if data is None else
                                               {"status":"OBSERVED",**classify(member,data)})
                    except ERRORS as exc:
                        row["members"][member]={"status":"REVIEW_REQUIRED","reason":str(exc)}
                reader.verify_unchanged()
                row["status"]="SELECTED_APEX_MEMBERS_STATIC_ONLY"
            except ERRORS as exc:
                row["reason"]=str(exc)
        if digest(private,4*1024**3)["sha256"]!=pin or digest(image,4*1024**3)["sha256"]!=pin:
            raise ValueError("System changed")
    result={"schema":"galwear-r800-wear51-apex-runtime-v1","source_sha":source,
            "system_sha256":pin,"modules":modules,"status":"REVIEW_REQUIRED",
            "runtime_executed":False,"art_initialized":False,"apex_activation_verified":False,
            "hardware_tested":False,"safe_to_flash":False}
    runtime=modules["com.android.runtime"]
    if runtime["status"]=="SELECTED_APEX_MEMBERS_STATIC_ONLY" and all(
            runtime["members"].get(p,{}).get("status")=="OBSERVED" and
            runtime["members"][p].get("abi")=="arm" for p in REQUIRED_RUNTIME):
        try:
            extracted=extract(image,pin,output)
            if (extracted["apex_layout"]!="PACKAGED_APEX" or
                    extracted["apex_sha256"]!=runtime["package_sha256"] or
                    extracted["apex_payload_sha256"]!=runtime["package"]["payload_sha256"] or
                    extracted["raw_system_sha256"]!=pin):
                raise ValueError("Extracted runtime differs from inspected APEX")
            for name in ("linker","libc.so","libm.so","libdl.so"):
                member="/bin/linker" if name=="linker" else "/lib/bionic/"+name
                if extracted["files"][name]["sha256"]!=runtime["members"][member]["sha256"]:
                    raise ValueError("Runtime member differs from inspected APEX")
            result["minimal_runtime"]=extracted
            result["status"]="WEAR51_MINIMAL_ARM32_RUNTIME_STATIC_ONLY"
        except ERRORS as exc:
            result["minimal_runtime_review"]=str(exc)
    checkout_sha(source)
    return result
