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


def arguments(classpath,*,compiler_filter="verify"):
    if compiler_filter not in ("verify","speed"):
        raise ValueError("Unsupported experimental compiler filter")
    expected=[ART_ROOT+"/javalib/"+n for n in BOOT_JARS]
    if classpath!=expected:
        raise ValueError("Unexpected boot classpath")
    return [ART_ROOT+"/bin/dex2oat32",
            *("--dex-file="+p for p in classpath),
            *("--dex-location="+p for p in classpath),
            "--image=/data/boot.art","--oat-file=/data/boot.oat",
            "--output-vdex=/data/boot.vdex","--base=0x70000000",
            "--instruction-set=arm","--instruction-set-variant=generic",
            "--compiler-filter="+compiler_filter,"--single-image","-j1",
            "--runtime-arg","-Xms64m","--runtime-arg","-Xmx512m"]


def oat_segments(raw):
    """Bounded ELF32 program header observation, not machine code validation."""
    if len(raw)<52 or raw[:7]!=b"\x7fELF\x01\x01\x01":
        raise ValueError("Expected little endian ELF32")
    kind,machine=struct.unpack_from("<HH",raw,16)
    phoff=struct.unpack_from("<I",raw,28)[0]
    ehsize,entsize,count=struct.unpack_from("<HHH",raw,40)
    if kind!=3 or machine!=40 or ehsize!=52 or entsize!=32 or not 1<=count<=128 or phoff<52 or phoff+count*entsize>len(raw):
        raise ValueError("Invalid ARM32 OAT program headers")
    loads=[]
    for i in range(count):
        kind,offset,vaddr,_,filesz,memsz,flags,align=struct.unpack_from("<8I",raw,phoff+i*entsize)
        if kind!=1:
            continue
        if filesz>memsz or offset+filesz>len(raw) or vaddr+memsz>2**32:
            raise ValueError("OAT LOAD outside bounds")
        if align not in (0,1) and (align&(align-1) or offset%align!=vaddr%align):
            raise ValueError("OAT LOAD alignment mismatch")
        loads.append({"offset":offset,"vaddr":vaddr,"file_bytes":filesz,"memory_bytes":memsz,
                      "flags":flags,"executable":bool(flags&1)})
    if not loads:
        raise ValueError("Missing OAT LOAD segments")
    return {"load_segments":loads,"executable_file_bytes":sum(x["file_bytes"] for x in loads if x["executable"]),
            "machine_code_validated":False}


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
        if name=="boot.oat" and valid:
            try:
                rows[name]["elf_segments"]=oat_segments(raw)
            except ValueError as exc:
                rows[name].update(status="REVIEW_REQUIRED",reason=str(exc))
    return rows
