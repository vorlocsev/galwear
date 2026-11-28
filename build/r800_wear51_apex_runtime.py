#!/usr/bin/env python3
"""Read selected ARM32 Bionic/ART from pinned Wear OS 5.1 System.

Static by default; optional isolated QEMU ART startup probe. No host mounts,
APEX activation, trusted signature or boot claim.
"""
import hashlib
from pathlib import Path
import shutil
import subprocess
import tempfile
import zipfile

from r800_art_apex_mapping import ApexReader
from r800_wear51_apex_container import inspect_container
from r800_wear51_art_dependencies import audit as art_dependency_audit
from r800_apex_inventory import package_inventory
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
    "com.android.os.statsd":("/system/apex/com.google.android.os.statsd.apex",
        ("/lib/libstatspull.so","/lib/libstatssocket.so")),
    "com.android.i18n":("/system/apex/com.android.i18n.apex",
        ("/lib/libicu.so","/lib/libicuuc.so","/lib/libicui18n.so")),
    "com.android.art":("/system/apex/com.google.android.art.apex",
        ("/bin/dex2oat32","/bin/dex2oat64","/bin/dex2oat","/lib/libart.so",
         "/lib/libartbase.so","/javalib/core-oj.jar","/javalib/core-libart.jar")),
}
REQUIRED_RUNTIME=("/bin/linker","/lib/bionic/libc.so","/lib/bionic/libm.so","/lib/bionic/libdl.so")
ERRORS=(OSError,ValueError,RuntimeError,KeyError,zipfile.BadZipFile,subprocess.SubprocessError)


def audit(image,pin,source,output,*,probe_art=False,qemu_compare=None):
    if qemu_compare is not None and not probe_art:
        raise ValueError("Comparator requires explicit ART probe")
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
    art_dependencies={"status":"NOT_TESTED"}
    art_startup={"status":"NOT_TESTED"}
    vm={"status":"NOT_TESTED"}
    with tempfile.TemporaryDirectory(prefix="wear51-apex-",dir=output.parent) as tmp:
        scratch=Path(tmp)
        private=scratch/"system.img"
        snapshot_image(image,private,pin)
        sources={"system":(tool,private,scratch)}
        readers=[]
        for module,(path,paths) in MODULES.items():
            row={"status":"REVIEW_REQUIRED","members":{}}
            modules[module]=row
            try:
                raw=ext4_member(tool,private,path,MAX_APEX,scratch)
                if raw is None:
                    raise ValueError("Expected observed APEX package")
                row["package_sha256"]=hashlib.sha256(raw).hexdigest()
                row["package_bytes"]=len(raw)
                row["container"],nested=inspect_container(raw,module)
                del raw
                directory=scratch/module
                directory.mkdir()
                if nested is not None and module not in ("com.android.art","com.android.os.statsd","com.android.i18n"):
                    raise ValueError("Nested wrapper only supported for selected ART, StatsD and i18n")
                actual_pin=row["container"].get("nested_sha256",row["package_sha256"])
                def read_partition(requested,limit):
                    if requested!=path:
                        raise ValueError("Unexpected APEX path")
                    if nested is not None:
                        if len(nested)>limit:
                            raise ValueError("Nested APEX exceeds reader budget")
                        return nested
                    return ext4_member(tool,private,path,limit,directory)
                reader=ApexReader([(module,path,actual_pin)],read_partition,directory)
                apex_tool,payload,workspace,package,*_=reader.open(module)
                row["package"]=reader.evidence[module]
                if nested is not None:
                    if row["container"]["wrapper_identity"]!=row["package"]["identity"]:
                        raise ValueError("Nested and wrapper APEX identities differ")
                    key=row["container"].get("wrapper_pubkey_sha256")
                    if key is not None and package_inventory(package)["pubkey_sha256"]!=key:
                        raise ValueError("Nested and wrapper APEX keys differ")
                for member in paths:
                    try:
                        data=ext4_member(apex_tool,payload,member,MAX_MEMBER,workspace)
                        row["members"][member]=({"status":"NOT_FOUND"} if data is None else
                                               {"status":"OBSERVED",**classify(member,data)})
                    except ERRORS as exc:
                        row["members"][member]={"status":"REVIEW_REQUIRED","reason":str(exc)}
                reader.verify_unchanged()
                row["status"]="SELECTED_APEX_MEMBERS_STATIC_ONLY"
                sources[module.rsplit(".",1)[-1]]=(apex_tool,payload,workspace)
                readers.append(reader)
            except ERRORS as exc:
                row["reason"]=str(exc)
        if {"system","runtime","art"} <= set(sources):
            try:
                art_dependencies=art_dependency_audit({k:v for k,v in sources.items() if k!="i18n"})
                for reader in readers:
                    reader.verify_unchanged()
            except (OverflowError,) + ERRORS as exc:
                art_dependencies={"status":"REVIEW_REQUIRED","reason":str(exc)}
        if {"system","runtime","art","statsd"} <= set(sources):
            try:
                from r800_wear51_art_dependencies import audit_vm
                vm=audit_vm(sources)
                for reader in readers:
                    reader.verify_unchanged()
            except (OverflowError,) + ERRORS as exc:
                vm={"status":"REVIEW_REQUIRED","reason":str(exc),"safe_to_flash":False}
        if probe_art:
            try:
                from r800_wear51_art_probe import probe
                art_startup=probe(sources,art_dependencies,scratch,source,pin,qemu_compare=qemu_compare)
                for reader in readers:
                    reader.verify_unchanged()
            except (OverflowError,) + ERRORS as exc:
                art_startup={"status":"REVIEW_REQUIRED","reason":str(exc),"safe_to_flash":False}
        if digest(private,4*1024**3)["sha256"]!=pin or digest(image,4*1024**3)["sha256"]!=pin:
            raise ValueError("System changed")
    result={"schema":"galwear-r800-wear51-apex-runtime-v1","source_sha":source,
            "system_sha256":pin,"modules":modules,"art_dependencies":art_dependencies,
            "art_startup":art_startup,"dalvikvm":vm,"status":"REVIEW_REQUIRED",
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
