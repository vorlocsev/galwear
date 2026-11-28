#!/usr/bin/env python3
"""Inventory static ELF dependencies of selected pinned Linux assembly tools.

No ldd, loader invocation, guest execution, mount or package installation.
Explicit standard-directory candidates are not actual glibc resolution.
"""
import argparse
import json
from pathlib import Path
import os

from r800_gps_host_elf import audit, DEFAULT_DIRS, LOADER, LIMIT, MAX_OBJECTS, MAX_EDGES, MAX_TOTAL, NAME
from r800_linux_assembly_environment import identity, read_pinned, TOOLS
from r800_stage_adaptation_layer import valid_pin
from r800_donor_preflight import digest
from r800_extract_super import require
from r800_graphics_donor_binding import checkout_sha

LIBRARY_ROOTS=(Path("/usr/lib"),Path("/usr/lib64"),Path("/lib"),Path("/lib64"))


def inventory(lock,source_sha):
    require(lock["source_sha"]==source_sha and set(lock["tools"])==set(TOOLS),
            "Expected exact-head selected host tool lock")
    tools={name:Path(row["resolved"]) for name,row in lock["tools"].items()}
    report=audit(tools)
    problems=list(report["problems"])
    objects,bindings=report["objects"],report["bindings"]
    root_paths={str(p) for p in tools.values()}
    for name,row in lock["tools"].items():
        target=bindings.get(name)
        obj=objects.get(target,{})
        if target!=row["resolved"] or any(obj.get(k)!=row[k] for k in ("bytes","sha256")):
            problems.append({"object":name,"reason":"TOOL_LOCK_MISMATCH_OR_UNSUPPORTED_ELF"})
    for key,row in objects.items():
        path=Path(key)
        if not path.is_absolute() or not (key in root_paths or
                any(path.is_relative_to(root) for root in LIBRARY_ROOTS)):
            problems.append({"object":key,"reason":"OUTSIDE_APPROVED_HOST_PATHS"})
            continue
        if path.resolve(strict=True)!=path or digest(path,LIMIT)!={
                "bytes":row["bytes"],"sha256":row["sha256"]}:
            problems.append({"object":key,"reason":"OBJECT_CHANGED"})
        if row["interpreter"] and bindings.get(LOADER) not in objects:
            problems.append({"object":key,"reason":"LOADER_NOT_IN_INVENTORY"})
        for dep in row["needed"]:
            if bindings.get(dep) not in objects:
                problems.append({"object":key,"needed":dep,"reason":"UNRESOLVED_PROVIDER"})
    return {"status":"SELECTED_HOST_ELF_CANDIDATES_ONLY" if not problems else "HOST_ELF_REVIEW_REQUIRED",
            "source_sha":source_sha,"roots":sorted(tools),"objects":objects,"bindings":bindings,
            "candidate_directories":list(DEFAULT_DIRS),"problems":problems,
            "loader_search_verified":False,"dlopen_coverage_verified":False,
            "runtime_verified":False,"complete_environment_verified":False,
            "reproducible_build_verified":False,"safe_to_flash":False}


def review_saved(lock,report,lock_pin,source_sha):
    require(lock.get("source_sha")==source_sha and set(lock["tools"])==set(TOOLS),
            "Expected exact-head selected host tool lock")
    require(isinstance(report,dict) and set(report)=={
        "schema","environment_lock_sha256","status","source_sha","roots","objects","bindings",
        "candidate_directories","problems","loader_search_verified","dlopen_coverage_verified",
        "runtime_verified","complete_environment_verified","reproducible_build_verified","safe_to_flash"} and
        report["schema"]=="galwear-r800-linux-host-elf-lock-v1" and
        report["environment_lock_sha256"]==lock_pin and report["source_sha"]==source_sha and
        report["status"]=="SELECTED_HOST_ELF_CANDIDATES_ONLY" and report["problems"]==[] and
        report["roots"]==sorted(TOOLS) and report["candidate_directories"]==list(DEFAULT_DIRS) and
        all(report[k] is False for k in ("loader_search_verified","dlopen_coverage_verified",
            "runtime_verified","complete_environment_verified","reproducible_build_verified","safe_to_flash")),
        "Unexpected saved host ELF scope or lock binding")
    objects,bindings=report["objects"],report["bindings"]
    require(isinstance(objects,dict) and 0<len(objects)<=MAX_OBJECTS and
            isinstance(bindings,dict),"Invalid host ELF inventory")
    roots={row["resolved"] for row in lock["tools"].values()}
    for key,row in objects.items():
        path=Path(key)
        require(path.is_absolute() and ".." not in path.parts and str(path)==key and
                (key in roots or any(path.is_relative_to(r) for r in LIBRARY_ROOTS)),
                "Invalid saved host ELF object path")
        require(isinstance(row,dict) and set(row)=={"bytes","sha256","needed","interpreter"} and
                type(row["bytes"]) is int and 0<row["bytes"]<=LIMIT and valid_pin(row["sha256"]) and
                row["interpreter"] in (None,LOADER) and isinstance(row["needed"],list) and
                len(row["needed"])<=MAX_EDGES and all(isinstance(n,str) and NAME.fullmatch(n) and
                n not in (".","..") for n in row["needed"]) and
                len(set(row["needed"]))==len(row["needed"]),"Invalid saved host ELF object")
    require(sum(r["bytes"] for r in objects.values())<=MAX_TOTAL and
            sum(len(r["needed"]) for r in objects.values())<=MAX_EDGES,"Saved ELF budget exceeded")
    for name,row in lock["tools"].items():
        target=bindings.get(name)
        obj=objects.get(target,{})
        require(target==row["resolved"] and all(obj.get(k)==row[k] for k in ("bytes","sha256")),
                "Saved host ELF root differs from executable lock")
    pending=list(TOOLS)
    used_labels=set()
    used_objects=set()
    while pending:
        label=pending.pop()
        if label in used_labels:
            continue
        used_labels.add(label)
        target=bindings.get(label)
        require(isinstance(target,str) and target in objects,"Missing saved host ELF provider")
        if target in used_objects:
            continue
        used_objects.add(target)
        row=objects[target]
        pending.extend(row["needed"])
        if row["interpreter"]:
            pending.append(LOADER)
    require(used_labels==set(bindings) and used_objects==set(objects),
            "Unexpected unreachable host ELF entries")
    return "SAVED_STATIC_HOST_ELF_CHAIN_ONLY"


def capture(lock_path,lock_pin,source_sha):
    checkout_sha(source_sha)
    require(os.environ.get("PATH")=="/usr/sbin:/usr/bin:/sbin:/bin","Set documented system PATH")
    raw,lock=read_pinned(lock_path,lock_pin)
    require(lock==identity(source_sha),"Selected host tools differ from lock")
    observed=inventory(lock,source_sha)
    require(inventory(lock,source_sha)==observed,"Host ELF inventory changed")
    require(identity(source_sha)==lock and read_pinned(lock_path,lock_pin)[0]==raw,
            "Host tools or environment lock changed")
    checkout_sha(source_sha)
    return {"schema":"galwear-r800-linux-host-elf-lock-v1",
            "environment_lock_sha256":lock_pin,**observed}


def verify(lock_path,lock_pin,report_path,report_pin,source_sha):
    raw,expected=read_pinned(report_path,report_pin)
    current=capture(lock_path,lock_pin,source_sha)
    require(current==expected,"Selected host ELF inventory differs from pinned report")
    require(read_pinned(report_path,report_pin)[0]==raw,"Host ELF report changed")
    return current


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--mode",choices=("capture","check"),required=True)
    p.add_argument("--lock",type=Path,required=True)
    p.add_argument("--lock-sha256",required=True)
    p.add_argument("--source-sha",required=True)
    p.add_argument("--report",type=Path)
    p.add_argument("--report-sha256")
    a=p.parse_args()
    if a.mode=="capture":
        require(a.report is None and a.report_sha256 is None,"Capture writes report to stdout")
        result=capture(a.lock,a.lock_sha256,a.source_sha)
    else:
        require(a.report is not None and a.report_sha256 is not None,"Pinned ELF report required")
        result=verify(a.lock,a.lock_sha256,a.report,a.report_sha256,a.source_sha)
    print(json.dumps(result,indent=2,sort_keys=True))
    return 0 if result["status"]=="SELECTED_HOST_ELF_CANDIDATES_ONLY" else 2


if __name__=="__main__":
    raise SystemExit(main())
