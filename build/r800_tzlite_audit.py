#!/usr/bin/env python3
"""Read-only audit of the known tzlite component list, not a runnable-root certification."""
import argparse
import json
from pathlib import Path
import stat
import struct

from r800_tizen_dependencies import audit, resolve_guest
from r800_tizen_gnss_preflight import config_evidence, metadata

# Explicit baseline from src/tools/tzlite/mktzlite.py; do not import the
# legacy root-only copier (it has top-level side effects).
PROGRAMS=tuple("/usr/bin/"+n for n in (
    "lhd","gpsd","sensord","sensorctl","env","chown","bash","sh","ls","cat"))
PLUGINS=tuple("/usr/lib/"+n for n in (
    "libbrcm.so","libnss_files.so.2","libnss_dns.so.2",
    "libSLP-tapi.so.0","libcontext-client.so.4",
    "libcontext-sensor-recorder-client-genuine.so.4","libcontext-shared.so.4",
    "libtracker.so.1","libwrappergps.so.0","libjson-glib-1.0.so.0",
    "libgdbm.so.3","libunwind.so.8"))
TARGETS=PROGRAMS+PLUGINS
MOUNTPOINTS=("/dev","/proc","/sys","/tmp","/run","/opt","/mnt")
REQUIRED_TREES=("/usr/lib/sensor","/etc/lhd","/etc/gps-manager")


def closure_problems(closure):
    problems=[]
    if closure["problems"]:
        problems.append("TZLITE_DEPENDENCY_REVIEW")
    for name,item in closure["files"].items():
        if item["arm_flags"]&0xff000000!=0x05000000 or item["arm_flags"]&0x400:
            problems.append("TZLITE_ARM_ABI_REVIEW:"+name)
        if not item["has_dynamic"] or item["dynamic_symbol_count"] is None:
            problems.append("TZLITE_SYMBOL_INVENTORY_REVIEW:"+name)
    symbols=closure["symbol_candidates"]
    if symbols["limit_exceeded"]:
        problems.append("TZLITE_SYMBOL_BUDGET_EXCEEDED")
    if closure["relocation_review_objects"]:
        problems.append("TZLITE_RELOCATION_REVIEW")
    for target in TARGETS:
        obj=closure["files"].get(closure["aliases"].get(target))
        scope=symbols["targets"].get(target)
        if obj is None or scope is None:
            problems.append("TZLITE_TARGET_MISSING:"+target)
            continue
        if scope["inventory_incomplete"] or scope["incomplete"] or scope["missing_strong"] or scope["ambiguous"]:
            problems.append("TZLITE_SYMBOL_SCOPE_REVIEW:"+target)
        if target in PLUGINS and obj["elf_type"]!="ET_DYN":
            problems.append("TZLITE_PLUGIN_TYPE_REVIEW:"+target)
        if target in PROGRAMS and obj["interpreter"]!="/lib/ld-linux.so.3":
            problems.append("TZLITE_PROGRAM_INTERPRETER_REVIEW:"+target)
    return problems


def check(root):
    root=root.resolve(strict=True)
    if root==Path("/") or not root.is_dir():
        raise ValueError("Expected isolated prepared tzlite directory")
    closure=audit(root,TARGETS)
    problems=closure_problems(closure)
    config=config_evidence(root)
    problems.extend(config["problems"])
    dirs={p:metadata(root,p) for p in MOUNTPOINTS+REQUIRED_TREES}
    for path,record in dirs.items():
        if record.get("kind")!="directory":
            problems.append("TZLITE_DIRECTORY_REVIEW:"+path)
    for guest in PROGRAMS:
        try:
            path,_=resolve_guest(root,guest)
            st=path.lstat()
            if not stat.S_ISREG(st.st_mode) or not st.st_mode&0o111:
                raise ValueError("Expected regular executable")
        except (OSError,ValueError):
            problems.append("TZLITE_PROGRAM_MODE_REVIEW:"+guest)
    return {"schema":"r800-tzlite-audit-v1",
            "status":"TZLITE_KNOWN_STATIC_CANDIDATES_ONLY" if not problems else "REVIEW_REQUIRED",
            "problems":problems,"dependency_evidence":closure,
            "configuration_evidence":config,"directories":dirs,
            "known_targets":list(TARGETS),"plugin_completeness_verified":False,
            "runtime_mounts_verified":False,"configuration_semantics_verified":False,
            "original_donor_verified":False,"gnss_runtime_verified":False,"safe_to_flash":False}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--root",type=Path,required=True)
    a=p.parse_args()
    try:
        report=check(a.root)
    except (OSError,ValueError,struct.error) as exc:
        report={"status":"REVIEW_REQUIRED","problems":[str(exc)],"safe_to_flash":False}
    print(json.dumps(report,indent=2,sort_keys=True))
    return 2 if report["problems"] else 0


if __name__=="__main__":
    raise SystemExit(main())
