#!/usr/bin/env python3
"""Read-only inventory of selected system Python stdlib and native extensions.

No imports of discovered modules, no guest execution or installation.
Does not certify actual Python import resolution or third-party packages.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import sysconfig

from r800_linux_assembly_environment import identity, read_pinned
from r800_gps_host_elf import audit, LIMIT
from r800_donor_preflight import digest
from r800_extract_super import require
from r800_graphics_donor_binding import checkout_sha

MAX_FILES=4096
MAX_TOTAL=512*1024**2
MAX_ENTRIES=8192
EXCLUDED={"site-packages","dist-packages"}
LIB_ROOTS=(Path("/usr/lib"),Path("/usr/lib64"),Path("/lib"),Path("/lib64"))


def file_pin(path):
    # The standard library can contain legitimate empty __init__.py files.
    before=path.lstat()
    require(stat.S_ISREG(before.st_mode),"Expected regular Python runtime file")
    if before.st_size:
        return digest(path,LIMIT)
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    try:
        require(os.fstat(fd)==before and os.read(fd,1)==b"" and
                os.fstat(fd)==before and path.lstat()==before,"Empty runtime file changed")
        return {"bytes":0,"sha256":hashlib.sha256(b"").hexdigest()}
    finally:
        os.close(fd)


def tree(root):
    root=Path(root)
    require(root.is_absolute() and root.resolve(strict=True)==root and root.is_dir(),
            "Canonical Python stdlib root required")
    files,excluded,problems={},[],[]
    total=entries=0
    pending=[root]
    while pending:
        parent=pending.pop()
        for path in sorted(parent.iterdir()):
            entries+=1
            require(entries<=MAX_ENTRIES,"Python runtime entry budget exceeded")
            rel=path.relative_to(root).as_posix()
            mode=path.lstat().st_mode
            if path.name in EXCLUDED:
                excluded.append(rel)
                continue
            if stat.S_ISDIR(mode):
                pending.append(path)
                continue
            if stat.S_ISLNK(mode):
                # Record the literal link; never follow arbitrary links.
                target=os.readlink(path)
                require(len(target)<=4096,"Python runtime symlink target exceeds budget")
                files[rel]={"kind":"symlink","target":target}
                problems.append({"path":rel,"reason":"SYMLINK_REQUIRES_REVIEW"})
            elif stat.S_ISREG(mode):
                row=file_pin(path)
                total+=row["bytes"]
                require(total<=MAX_TOTAL,"Python runtime byte budget exceeded")
                files[rel]={"kind":"regular",**row}
            else:
                problems.append({"path":rel,"reason":"SPECIAL_FILE_REQUIRES_REVIEW"})
            require(len(files)<=MAX_FILES,"Python runtime file budget exceeded")
    require(files,"Empty Python runtime inventory")
    encoded=json.dumps(files,sort_keys=True,separators=(",",":"),ensure_ascii=True).encode()
    return {"files":files,"tree_sha256":hashlib.sha256(encoded).hexdigest(),
            "file_count":len(files),"regular_bytes":total,"excluded":sorted(excluded),
            "problems":sorted(problems,key=lambda row:row["path"])}


def extensions(root,rows):
    selected={name:root/name for name,row in rows.items()
              if row["kind"]=="regular" and name.endswith(".so")}
    if not selected:
        return {"status":"HOST_REVIEW_REQUIRED","objects":{},"bindings":{},
                "problems":[{"reason":"No native extension files observed"}]}
    report=audit(selected)
    for name,path in selected.items():
        row=rows[name]
        obj=report["objects"].get(str(path),{})
        if report["bindings"].get(name)!=str(path) or any(
                obj.get(k)!=row[k] for k in ("bytes","sha256")):
            report["problems"].append({"object":name,"reason":"EXTENSION_PIN_MISMATCH"})
    for key,row in report["objects"].items():
        path=Path(key)
        if not any(path.is_relative_to(r) for r in LIB_ROOTS):
            report["problems"].append({"object":key,"reason":"OUTSIDE_SYSTEM_LIBRARY_ROOTS"})
            continue
        if path.resolve(strict=True)!=path or file_pin(path)!={
                "bytes":row["bytes"],"sha256":row["sha256"]}:
            report["problems"].append({"object":key,"reason":"NATIVE_OBJECT_CHANGED"})
    if report["problems"]:
        report["status"]="HOST_REVIEW_REQUIRED"
    return report


def capture(lock_path,lock_pin,source_sha):
    checkout_sha(source_sha)
    raw,lock=read_pinned(lock_path,lock_pin)
    require(lock==identity(source_sha),"Selected host tools differ from lock")
    require(sys.version_info[:2]==(3,12),"Expected Ubuntu 24.04 system Python 3.12")
    require(sys.dont_write_bytecode,"Use Python -B to avoid changing runtime caches")
    root=Path(sysconfig.get_path("stdlib"))
    require(root==Path("/usr/lib/python3.12"),"Unexpected system stdlib root")
    inventory=tree(root)
    native=extensions(root,inventory["files"])
    require(tree(root)==inventory and extensions(root,inventory["files"])==native,
            "Python runtime inventory changed")
    require(identity(source_sha)==lock and read_pinned(lock_path,lock_pin)[0]==raw,
            "Host tools or environment lock changed")
    checkout_sha(source_sha)
    problems=bool(inventory["problems"] or native["status"]!="HOST_STATIC_CANDIDATES_ONLY")
    return {"schema":"galwear-r800-python-runtime-lock-v1","source_sha":source_sha,
            "environment_lock_sha256":lock_pin,"python_version":lock["python_version"],
            "stdlib_root":str(root),"stdlib":inventory,"native_extensions":native,
            "status":"PYTHON_RUNTIME_REVIEW_REQUIRED" if problems else
                     "SELECTED_PYTHON_RUNTIME_BYTES_AND_ELF_CANDIDATES_ONLY",
            "actual_import_resolution_verified":False,"third_party_packages_verified":False,
            "dlopen_coverage_verified":False,"reproducible_build_verified":False,
            "hardware_tested":False,"safe_to_flash":False}


def verify(lock_path,lock_pin,report_path,report_pin,source_sha):
    raw,expected=read_pinned(report_path,report_pin)
    current=capture(lock_path,lock_pin,source_sha)
    require(current==expected,"Python runtime differs from pinned report")
    require(read_pinned(report_path,report_pin)[0]==raw,"Python runtime report changed")
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
        require(a.report is not None and a.report_sha256 is not None,"Pinned report required")
        result=verify(a.lock,a.lock_sha256,a.report,a.report_sha256,a.source_sha)
    print(json.dumps(result,sort_keys=True,separators=(",",":")))
    return 0 if result["status"]=="SELECTED_PYTHON_RUNTIME_BYTES_AND_ELF_CANDIDATES_ONLY" else 2


if __name__=="__main__":
    raise SystemExit(main())
