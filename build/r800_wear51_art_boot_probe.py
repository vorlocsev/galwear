#!/usr/bin/env python3
"""Stage selected original ART boot jars and inspect experimental compiler outputs.

This is not a full device boot classpath or a releasable boot image.
"""
import hashlib
from pathlib import Path
import stat
import struct

from r800_framework_inventory import ext4_member, classify, MAX_MEMBER
from r800_pixel_runtime_layout import list_directory
from r800_android_userspace_preflight import read_regular

BOOT_JARS=("core-oj.jar","core-libart.jar","okhttp.jar","bouncycastle.jar","apache-xml.jar")
MAX_BOOT_JARS=64*1024**2
MAX_OUTPUT=64*1024**2
ART_ROOT="/apex/com.android.art"
OUTPUTS=("boot.art","boot.oat","boot.vdex")


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def stage(sources,guest):
    tool,image,scratch=sources["art"]
    directory=list_directory(tool,image,"/javalib")
    arm=list_directory(tool,image,"/javalib/arm")
    rows={}
    total=0
    target=guest/"apex/com.android.art/javalib"
    target.mkdir(parents=True,exist_ok=True)
    for name in BOOT_JARS:
        raw=ext4_member(tool,image,"/javalib/"+name,min(MAX_MEMBER,MAX_BOOT_JARS-total),scratch)
        if raw is None:
            rows[name]={"status":"NOT_FOUND"}
            continue
        total+=len(raw)
        if total>MAX_BOOT_JARS:
            raise ValueError("ART boot JAR budget exceeded")
        info=classify("/javalib/"+name,raw,validate_dex=True)
        if info["kind"]!="JAR_DEX_HEADER_INVENTORY_ONLY" or not info["dex_entries"]:
            raise ValueError("Missing embedded DEX: "+name)
        with (target/name).open("xb") as stream:
            stream.write(raw)
        (target/name).chmod(0o444)
        rows[name]={"status":"OBSERVED",**info}
    return {"status":"SELECTED_ART_BOOT_JARS_ONLY" if all(
        rows[n]["status"]=="OBSERVED" for n in BOOT_JARS) else "REVIEW_REQUIRED",
        "members":rows,"javalib_listing":directory,"arm_listing":arm,
        "classpath":[ART_ROOT+"/javalib/"+n for n in BOOT_JARS],
        "full_device_boot_classpath_verified":False,"dex_bytecode_verified":False,
        "safe_to_flash":False}


def arguments(classpath):
    expected=[ART_ROOT+"/javalib/"+n for n in BOOT_JARS]
    if classpath!=expected:
        raise ValueError("Unexpected boot classpath")
    return [ART_ROOT+"/bin/dex2oat32",
            *("--dex-file="+p for p in classpath),
            *("--dex-location="+p for p in classpath),
            "--image=/data/boot.art","--oat-file=/data/boot.oat",
            "--output-vdex=/data/boot.vdex","--base=0x70000000",
            "--instruction-set=arm","--instruction-set-variant=generic",
            "--compiler-filter=verify","--single-image","-j1",
            "--runtime-arg","-Xms64m","--runtime-arg","-Xmx512m"]


def inspect_outputs(directory):
    rows={}
    total=0
    for name in OUTPUTS:
        path=directory/name
        try:
            st=path.lstat()
        except FileNotFoundError:
            rows[name]={"status":"NOT_FOUND"}
            continue
        if not stat.S_ISREG(st.st_mode) or not 16<=st.st_size<=MAX_OUTPUT-total:
            rows[name]={"status":"REVIEW_REQUIRED","reason":"Invalid output type or length"}
            continue
        raw=read_regular(path,MAX_OUTPUT-total)
        total+=len(raw)
        if name=="boot.art":
            valid=raw[:4]==b"art\n" and raw[4:7].isdigit() and raw[7]==0
        elif name=="boot.vdex":
            valid=raw[:4]==b"vdex" and raw[4:7].isdigit() and raw[7]==0
        else:
            valid=(len(raw)>=52 and raw[:7]==b"\x7fELF\x01\x01\x01" and
                   struct.unpack_from("<H",raw,18)[0]==40 and
                   struct.unpack_from("<H",raw,16)[0]==3 and b"oat\n" in raw)
        rows[name]={"status":"HEADER_OBSERVED" if valid else "REVIEW_REQUIRED",
                    "sha256":sha(raw),"bytes":len(raw),"header_hex":raw[:16].hex()}
    return rows
