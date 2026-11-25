#!/usr/bin/env python3
"""Check the explicit experimental single-namespace DT_NEEDED model on EXT4.

This is not Bionic execution, symbol relocation, or an audit of all donor
APEX files. System directories must contain only the generated inventory.
The mounted APEX contains the complete donor payload.
"""
import argparse
import json
from pathlib import Path, PurePosixPath
import posixpath
import re

from r800_android_init_rootfs import CONFIG, SEARCH
from r800_android_rootfs_preflight import sha
from r800_android_dynamic_audit import RUNTIME, LIBS
from r800_qemu_readonly_disks import report

STATUS = "EXT4_LINKER_RESOLUTION_STATIC_ONLY"
ROOTS = ("system/bin/galwear_property_service","system/bin/galwear_property_client")
LINK = "system/bin/linker64"
HASH = re.compile(r"[0-9a-f]{64}")
LIB = re.compile(r"[A-Za-z0-9_.+-]+\.so")


def evaluate(system, runtime):
    if system["policy_sha256"] != runtime["policy_sha256"]:
        raise ValueError("Different image policy identities")
    entries=system["verified_system_entries"]
    staged=system["staged_elf_metadata"]
    choices=system["selected_libraries"]
    if (system.get("service_fixture") is not True
            or entries["system/etc/ld.config.txt"]["sha256"] != sha(CONFIG)
            or system["experimental_linker_config_sha256"] != sha(CONFIG)):
        raise ValueError("Unexpected experimental linker config")
    actual={}
    for rel,info in staged.items():
        if rel.startswith("system/"):
            inode=entries[rel]
            if inode["type"]!="regular" or inode["sha256"]!=info["sha256"]:
                raise ValueError("System ELF digest mismatch: "+rel)
            actual[rel]=info
        elif not rel.startswith(RUNTIME+"/"):
            raise ValueError("Unexpected staged ELF path")
    for rel,inode in runtime["selected_inode_labels"].items():
        if "elf" not in inode:
            continue
        key=RUNTIME+rel
        info=inode["elf"]
        if inode["sha256"]!=info["sha256"]:
            raise ValueError("APEX ELF digest mismatch: "+key)
        if key in staged and staged[key]!=info:
            raise ValueError("Staged and donor ELF metadata mismatch: "+key)
        actual[key]=info
    if not set(staged)<=set(actual):
        raise ValueError("Staged ELF not present in actual images")
    for lib in LIBS:
        if RUNTIME+"/lib64/bionic/"+lib not in actual:
            raise ValueError("Incomplete audited Bionic inventory")
    if RUNTIME+"/bin/linker64" not in actual:
        raise ValueError("Missing audited Runtime linker")
    for rel,info in actual.items():
        if info["elf_type"]!=3 or not HASH.fullmatch(info["sha256"]):
            raise ValueError("Invalid ELF identity: "+rel)

    def interpreter(rel):
        value=actual[rel]["interpreter"]
        if value not in ("/system/bin/linker64","/system/bin/bootstrap/linker64"):
            raise ValueError("Unexpected PT_INTERP: "+rel)
        key=value[1:]
        if key==LINK and entries[key]["type"]=="symlink":
            target=entries[key]["target"]
            if target not in ("../../apex/com.android.runtime/bin/linker64","bootstrap/linker64"):
                raise ValueError("Unexpected linker alias")
            key=posixpath.normpath(posixpath.join("system/bin",target))
        info=actual.get(key)
        if info is None or info["interpreter"] is not None or info["needed"]:
            raise ValueError("Missing or invalid resolved linker: "+key)
        if key not in staged:
            raise ValueError("Interpreter not explicitly staged: "+key)
        return key

    def resolve(name):
        if not LIB.fullmatch(name) or name not in choices:
            raise ValueError("Missing explicit dependency selection: "+name)
        origin,chosen=choices[name].split(":",1)
        if origin not in ("product","runtime"):
            raise ValueError("Invalid dependency origin")
        candidates=[directory.lstrip("/")+"/"+name for directory in SEARCH]
        candidates=[p for p in candidates if p in actual]
        if not candidates or candidates[0]!=chosen:
            raise ValueError("Search order differs from staged selection: "+name)
        info=actual[chosen]
        if chosen not in staged or info["soname"]!=name or info["interpreter"] is not None:
            raise ValueError("Unexpected selected shared object: "+name)
        return chosen,candidates

    result={}
    for root in ROOTS:
        linker=interpreter(root)
        pending=[root]
        visited=set()
        edges=[]
        while pending:
            rel=pending.pop()
            if rel in visited:
                continue
            visited.add(rel)
            if len(visited)>256:
                raise ValueError("Dependency closure exceeds bounds")
            for name in actual[rel]["needed"]:
                chosen,candidates=resolve(name)
                edges.append({"from":"/"+rel,"needed":name,"resolved":"/"+chosen,
                              "sha256":actual[chosen]["sha256"],
                              "audited_candidates":["/"+p for p in candidates]})
                pending.append(chosen)
        result["/"+root]={"interpreter":"/"+linker,"interpreter_sha256":actual[linker]["sha256"],
                          "edges":sorted(edges,key=lambda x:(x["from"],x["needed"])),
                          "selected_elf_sha256":{"/"+p:actual[p]["sha256"] for p in sorted(visited)}}
    return {"status":STATUS,"policy_sha256":system["policy_sha256"],
            "system_sha256":system["image_sha256"],"runtime_sha256":runtime["payload_sha256"],
            "config_sha256":sha(CONFIG),"search_paths":list(SEARCH),"executables":result,
            "selected_inventory_model_only":True,"all_apex_files_audited":False,
            "symbol_relocations_tested":False,"namespace_resolution_tested":False,
            "safe_to_flash":False}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ("system-report","runtime-report","report"):
        p.add_argument("--"+name,type=Path,required=True)
    a=p.parse_args()
    try:
        result=evaluate(report(a.system_report,"ANDROID_SYSTEM_EXT4_SERVICE_STATIC_ONLY"),
                        report(a.runtime_report,"ANDROID_RUNTIME_APEX_PAYLOAD_PRESERVED_ONLY"))
        rc=0
    except (OSError,ValueError,TypeError,KeyError,AttributeError) as exc:
        result={"status":"REJECT","reason":str(exc),"safe_to_flash":False}
        rc=2
    a.report.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
    print(result["status"])
    return rc

if __name__=="__main__":
    raise SystemExit(main())
