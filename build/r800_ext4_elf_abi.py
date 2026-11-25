#!/usr/bin/env python3
"""Read-only static ABI audit of the selected Android 11 ELF closure.

No donor execution or host mount. GNU readelf output is inspected; matching
symbols are candidate evidence, not Bionic's actual symbol lookup decision.
"""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

from r800_android_dynamic_audit import inspect_elf, MAX_ELF, RUNTIME
from r800_android_runtime_extract import dump_file, digest, MAX_PAYLOAD
from r800_android_system_ext4 import IMAGE_SIZE
from r800_qemu_readonly_disks import report
from r800_ext4_linker_resolution import evaluate as resolve
from r800_elf_relocations import inspect as inspect_relocations

STATUS = "EXT4_ELF_ABI_STATIC_ADVISORY_ONLY"
ROW = re.compile(r"^\s*(\d+):\s+[0-9a-fA-F]+\s+\d+\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s*(.*?)\s*$")
SYMBOL = re.compile(r"([^@\s]+)(?:(@@?)([^@\s]+)(?:\s+\((\d+)\))?)?")
CAP = 100000
RELOCATION_TAGS = {"REL","RELSZ","RELENT","RELA","RELASZ","RELAENT",
                   "JMPREL","PLTREL","PLTRELSZ","RELR","RELRSZ","RELRENT",
                   "ANDROID_REL","ANDROID_RELSZ","ANDROID_RELA","ANDROID_RELASZ",
                   "ANDROID_RELR","ANDROID_RELRSZ","ANDROID_RELRENT","ANDROID_RELRCOUNT"}
ANDROID_TAGS = {0x6000000f:"ANDROID_REL",0x60000010:"ANDROID_RELSZ",
                0x60000011:"ANDROID_RELA",0x60000012:"ANDROID_RELASZ",
                0x6fffe000:"ANDROID_RELR",0x6fffe001:"ANDROID_RELRSZ",
                0x6fffe003:"ANDROID_RELRENT",0x6fffe005:"ANDROID_RELRCOUNT"}


def parse(text):
    needs={}
    provider=None
    for line in text.splitlines():
        m=re.search(r"\bFile:\s+(\S+)\s+Cnt:\s+\d+",line)
        if m:
            provider=m[1]
        m=re.search(r"\bName:\s+(\S+)\s+Flags:\s+.*?\s+Version:\s+(\d+)\s*$",line)
        if m:
            if provider is None or int(m[2]) in needs:
                raise ValueError("Ambiguous version need index")
            needs[int(m[2])]=(provider,m[1])
    imports,exports=[],[]
    declared=None
    seen=0
    for line in text.splitlines():
        m=re.search(r"Symbol table '\.dynsym' contains (\d+) entr",line)
        if m:
            if declared is not None:
                raise ValueError("Duplicate dynsym table")
            declared=int(m[1])
            continue
        m=ROW.fullmatch(line)
        if not m:
            continue
        if declared is None or int(m[1])!=seen:
            raise ValueError("Unexpected dynamic symbol row")
        seen+=1
        if seen>CAP:
            raise ValueError("Symbol count outside bounds")
        typ,bind,vis,ndx,raw=m.groups()[1:]
        if not raw:
            if int(m[1])==0:
                continue
            raise ValueError("Unnamed non-null dynamic symbol")
        name=SYMBOL.fullmatch(raw)
        if not name:
            raise ValueError("Unrecognized symbol/version syntax")
        symbol,marker,version,index=name.groups()
        if bind not in ("GLOBAL","WEAK","UNIQUE"):
            continue
        row={"name":symbol,"version":version,"type":typ,"weak":bind=="WEAK"}
        if ndx=="UND":
            if version:
                if index is None or int(index) not in needs or needs[int(index)][1]!=version:
                    raise ValueError("Missing version need provider")
                row["provider"]=needs[int(index)][0]
            imports.append(row)
        elif vis in ("DEFAULT","PROTECTED"):
            row["default_version"]=marker=="@@"
            exports.append(row)
    if declared is None or declared!=seen:
        raise ValueError("Incomplete dynamic symbol table")
    tags=set()
    for match in re.finditer(r"^\s*0x([0-9a-fA-F]+)\s+\(([^)]+)\)\s*(.*)$",text,re.M):
        tag=ANDROID_TAGS.get(int(match[1],16),match[2])
        if tag=="TEXTREL" or (tag=="FLAGS" and "TEXTREL" in match[3].split()):
            raise ValueError("Text relocations incompatible with AArch64 Bionic")
        if tag in RELOCATION_TAGS:
            tags.add(tag)
    if tags & {"REL","RELSZ","RELENT","ANDROID_REL","ANDROID_RELSZ"}:
        raise ValueError("REL encoding incompatible with AArch64 RELA linker")
    types=sorted(set(re.findall(r"\bR_AARCH64_[A-Z0-9_]+\b",text)))
    return {"imports":imports,"exports":exports,"dynamic_symbol_count":declared,"relocation_tags":sorted(tags),
            "visible_relocation_types":types}


def inspect(path,readelf="readelf"):
    before=inspect_elf(path,readelf)
    out=subprocess.run([readelf,"-W","--dyn-syms","-V","-d","-r",str(path)],
                       check=True,capture_output=True,text=True,timeout=30,
                       env={**os.environ,"LC_ALL":"C"})
    if out.stderr or len(out.stdout)>32*1024*1024:
        raise ValueError("ELF ABI inspection diagnostic or excessive output")
    result=parse(out.stdout)
    with path.open("rb") as stream:
        raw=stream.read(MAX_ELF+1)
    import hashlib
    if hashlib.sha256(raw).hexdigest()!=before["sha256"]:
        raise ValueError("ELF changed before relocation inspection")
    result["relocation_structure"]=inspect_relocations(raw,result["dynamic_symbol_count"])
    if digest(path,MAX_ELF)!=before["sha256"]:
        raise ValueError("ELF changed during ABI inspection")
    return {**result,"sha256":before["sha256"],"soname":before["soname"]}


def matches(need,export):
    if need["name"]!=export["name"]:
        return False
    if need["type"]=="TLS" or export["type"]=="TLS":
        if need["type"]!=export["type"]:
            return False
    if need["version"] is not None:
        return need["version"]==export["version"]
    return export["version"] is None or export["default_version"]


def summarize(closure,objects):
    results={}
    for root,plan in closure.items():
        paths=set(plan["selected_elf_sha256"])|{plan["interpreter"]}
        expected={**plan["selected_elf_sha256"],plan["interpreter"]:plan["interpreter_sha256"]}
        if any(objects[p]["sha256"]!=expected[p] for p in paths):
            raise ValueError("ABI object identity mismatch")
        providers={}
        for path in sorted(paths):
            for symbol in objects[path]["exports"]:
                providers.setdefault(symbol["name"],[]).append((path,symbol))
        missing,strong,weak,ambiguous=[],0,0,0
        checked=0
        for path in sorted(paths):
            for need in objects[path]["imports"]:
                checked+=1
                found=[p for p,exp in providers.get(need["name"],[]) if matches(need,exp)
                       and ("provider" not in need or objects[p]["soname"]==need["provider"])]
                if not found:
                    if need["weak"]:
                        weak+=1
                    else:
                        strong+=1
                    if len(missing)<100:
                        missing.append({"object":path,**need})
                elif len(set(found))>1:
                    ambiguous+=1
        results[root]={"import_count":checked,"missing_strong_candidates":strong,
                       "missing_weak_candidates":weak,"multiple_provider_candidates":ambiguous,
                       "missing_examples":missing,
                       "objects":{p:{"sha256":objects[p]["sha256"],
                                    "import_count":len(objects[p]["imports"]),
                                    "export_count":len(objects[p]["exports"]),
                                    "relocation_tags":objects[p]["relocation_tags"],
                                    "visible_relocation_types":objects[p]["visible_relocation_types"],
                                    "relocation_structure":objects[p].get("relocation_structure")}
                                  for p in sorted(paths)}}
    return results


def evaluate(system,runtime,system_image,runtime_image,readelf="readelf"):
    resolution=resolve(system,runtime)
    expected={system_image:(IMAGE_SIZE,system["image_sha256"]),
              runtime_image:(MAX_PAYLOAD,runtime["payload_sha256"])}
    for image,(limit,wanted) in expected.items():
        if digest(image,limit)!=wanted:
            raise ValueError("Image digest mismatch")
    files={}
    for plan in resolution["executables"].values():
        files.update(plan["selected_elf_sha256"])
        files[plan["interpreter"]]=plan["interpreter_sha256"]
    objects={}
    with tempfile.TemporaryDirectory(prefix="galwear-abi-",dir="/tmp") as tmp:
        for i,(path,wanted) in enumerate(sorted(files.items())):
            if path.startswith("/system/"):
                image,rel=system_image,path[len("/system"):]
            elif path.startswith("/"+RUNTIME+"/"):
                image,rel=runtime_image,path[len("/"+RUNTIME):]
            else:
                raise ValueError("Unexpected ABI object path")
            local=Path(tmp)/f"elf{i}"
            dump_file(image,rel,local,MAX_ELF)
            info=inspect(local,readelf)
            if info["sha256"]!=wanted:
                raise ValueError("Extracted ELF digest mismatch: "+path)
            objects[path]=info
    for image,(limit,wanted) in expected.items():
        if digest(image,limit)!=wanted:
            raise ValueError("Image changed during ABI audit")
    return {"status":STATUS,"policy_sha256":resolution["policy_sha256"],
            "system_sha256":resolution["system_sha256"],"runtime_sha256":resolution["runtime_sha256"],
            "executables":summarize(resolution["executables"],objects),
            "packed_relocations_decoded":all(o["relocation_structure"]["packed_relocations_decoded"] for o in objects.values()),
            "symbol_resolution_tested":False,
            "stub_exclusion_proven":False,"runtime_relocations_tested":False,
            "safe_to_flash":False}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ("system-report","runtime-report","system-image","runtime-image","report"):
        p.add_argument("--"+name,type=Path,required=True)
    p.add_argument("--readelf",default="readelf")
    a=p.parse_args()
    try:
        result=evaluate(report(a.system_report,"ANDROID_SYSTEM_EXT4_SERVICE_STATIC_ONLY"),
                        report(a.runtime_report,"ANDROID_RUNTIME_APEX_PAYLOAD_PRESERVED_ONLY"),
                        a.system_image,a.runtime_image,a.readelf)
        rc=0
    except (OSError,ValueError,KeyError,TypeError,AttributeError,RuntimeError,subprocess.SubprocessError) as exc:
        result={"status":"REJECT","reason":str(exc),"safe_to_flash":False}
        rc=2
    a.report.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
    print(result["status"])
    return rc

if __name__=="__main__":
    raise SystemExit(main())
