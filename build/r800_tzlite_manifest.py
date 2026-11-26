#!/usr/bin/env python3
"""Verify an isolated tzlite static candidate against an externally supplied manifest digest."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import posixpath
import re
import stat

from r800_tizen_dependencies import MAX_FILE, MAX_TOTAL

MANIFEST="tzlite-static-evidence.json"
MAX_ENTRIES=4096
MAX_MANIFEST=4*1024*1024
MAX_DEPTH=32


def fingerprint(st):
    return (st.st_dev,st.st_ino,st.st_mode,st.st_nlink,st.st_size,
            st.st_mtime_ns,st.st_ctime_ns)


def read_file(path,limit,*,capture=False):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    try:
        before=os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink!=1 or not 0<=before.st_size<=limit:
            raise ValueError("Expected bounded single-link regular file")
        digest=hashlib.sha256()
        data=bytearray()
        count=0
        while True:
            chunk=os.read(fd,min(1024*1024,limit-count+1))
            if not chunk:
                break
            count+=len(chunk)
            if count>limit:
                raise ValueError("File exceeds byte budget")
            digest.update(chunk)
            if capture:
                data.extend(chunk)
        if (count!=before.st_size or fingerprint(os.fstat(fd))!=fingerprint(before)
                or fingerprint(path.lstat())!=fingerprint(before)):
            raise ValueError("File changed during scan")
        return {"kind":"file","mode":oct(stat.S_IMODE(before.st_mode)),
                "bytes":count,"sha256":digest.hexdigest()},bytes(data)
    finally:
        os.close(fd)


def inventory(root):
    root=root.resolve(strict=True)
    if root==Path("/") or not root.is_dir():
        raise ValueError("Expected isolated static candidate directory")
    entries={}
    total=0
    def walk(directory,depth):
        nonlocal total
        if depth>MAX_DEPTH:
            raise ValueError("Candidate depth budget exceeded")
        before=directory.lstat()
        if not stat.S_ISDIR(before.st_mode):
            raise ValueError("Expected directory")
        with os.scandir(directory) as children:
            for child in children:
                p=Path(child.path)
                key="/"+p.relative_to(root).as_posix()
                if key=="/"+MANIFEST:
                    continue
                if len(entries)>=MAX_ENTRIES or not re.fullmatch(r"/[A-Za-z0-9_.+@/-]{1,1023}",key):
                    raise ValueError("Candidate entry budget or path review")
                st=p.lstat()
                mode=oct(stat.S_IMODE(st.st_mode))
                if stat.S_ISDIR(st.st_mode):
                    entries[key]={"kind":"directory","mode":mode}
                    walk(p,depth+1)
                elif stat.S_ISREG(st.st_mode):
                    rec,_=read_file(p,min(MAX_FILE,MAX_TOTAL-total))
                    total+=rec["bytes"]
                    entries[key]=rec
                elif stat.S_ISLNK(st.st_mode):
                    target=os.readlink(p)
                    if (target.startswith("/") or not re.fullmatch(r"[A-Za-z0-9_.+@/-]{1,1023}",target)
                            or fingerprint(p.lstat())!=fingerprint(st)):
                        raise ValueError("Unsafe or changed candidate link")
                    entries[key]={"kind":"symlink","target":target}
                else:
                    raise ValueError("Unsupported candidate object")
        if fingerprint(directory.lstat())!=fingerprint(before):
            raise ValueError("Directory changed during scan")
    walk(root,0)
    for name,item in entries.items():
        if item["kind"]!="symlink":
            continue
        # Reject traversal outside the candidate even if the path would
        # normalize back into it. Staging links point directly to files.
        parts=name.strip("/").split("/")[:-1]
        for part in item["target"].split("/"):
            if part in ("","."):
                continue
            if part=="..":
                if not parts:
                    raise ValueError("Candidate symlink escapes root")
                parts.pop()
            else:
                parts.append(part)
        target="/"+"/".join(parts)
        if entries.get(target,{}).get("kind")!="file":
            raise ValueError("Candidate symlink target is not an inventoried file")
    return {"root_mode":oct(stat.S_IMODE(root.lstat().st_mode)),
            "entries":entries,"total_bytes":total}


def verify(root,expected):
    if not re.fullmatch(r"[0-9a-f]{64}",expected):
        raise ValueError("Expected lowercase manifest SHA-256")
    root=root.resolve(strict=True)
    if root==Path("/") or not root.is_dir():
        raise ValueError("Expected isolated static candidate directory")
    path=root/MANIFEST
    info,raw=read_file(path,MAX_MANIFEST,capture=True)
    if info["sha256"]!=expected:
        raise ValueError("Manifest SHA-256 mismatch")
    report=json.loads(raw)
    if (not isinstance(report,dict) or report.get("schema")!="r800-tzlite-static-stage-v2"
            or report.get("status")!="TZLITE_STATIC_CANDIDATE_ONLY"
            or any(report.get(k) is not False for k in ("full_configuration_copied",
                "plugins_complete","ownership_preserved","runtime_verified","safe_to_flash"))
            or report.get("source_and_stage_audited") is not True):
        raise ValueError("Invalid static staging manifest")
    actual=inventory(root)
    if actual!=report.get("tree"):
        raise ValueError("Candidate inventory differs from manifest")
    if read_file(path,MAX_MANIFEST)[0]!=info:
        raise ValueError("Manifest changed during verification")
    return {"schema":"r800-tzlite-manifest-check-v1","status":"STATIC_TREE_INTEGRITY_ONLY",
            "manifest_sha256":expected,"entries":len(actual["entries"]),
            "total_bytes":actual["total_bytes"],"problems":[],
            "donor_authenticity_verified":False,"runtime_verified":False,"safe_to_flash":False}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--root",type=Path,required=True)
    p.add_argument("--sha256",required=True)
    a=p.parse_args()
    try:
        report=verify(a.root,a.sha256)
    except (OSError,ValueError,RecursionError) as exc:
        report={"status":"REVIEW_REQUIRED","problems":[str(exc)],"safe_to_flash":False}
    print(json.dumps(report,indent=2,sort_keys=True))
    return 2 if report["problems"] else 0


if __name__=="__main__":
    raise SystemExit(main())
