#!/usr/bin/env python3
"""Bounded inventory of the legacy tzlite config/plugin scope; never copy or execute."""
import argparse
import json
import os
from pathlib import Path
import re
import stat

from r800_tizen_dependencies import MAX_FILE, MAX_TOTAL
from r800_tizen_gnss_preflight import CONFIGS
from r800_tzlite_audit import REQUIRED_TREES
from r800_tzlite_manifest import read_file, fingerprint

FILES=("/etc/passwd","/etc/group","/etc/nsswitch.conf","/etc/hosts",
       "/etc/ld.so.cache","/etc/info.ini","/etc/deviced/device/power.conf",
       "/etc/sensor_cal.conf","/etc/system_info_db","/usr/etc/sensor.xml",
       "/etc/tizen-platform.conf","/etc/resolv.conf","/usr/lib/charset.alias",
       "/etc/localtime","/usr/lib/gconv/gconv-modules.cache")
LINKS=("/bin","/lib","/sbin","/var","/home","/media")
MAX_ENTRIES=4096
MAX_DEPTH=16
SAFE_NAME=re.compile(r"[A-Za-z0-9_.+@-]{1,255}")
SAFE_TARGET=re.compile(r"[A-Za-z0-9_.+@/-]{1,1023}")


def inspect(root):
    if root.is_symlink():
        raise ValueError("Expected nonsymlink donor root")
    root=root.resolve(strict=True)
    if root==Path("/") or not root.is_dir():
        raise ValueError("Expected isolated offline donor root")
    entries={}
    issues=set()
    watched={}
    total=0

    def observe(p,st):
        mark=fingerprint(st)+(st.st_uid,st.st_gid)
        if p in watched and watched[p]!=mark:
            raise ValueError("Donor metadata changed during inventory")
        watched[p]=mark

    def locate(name):
        current=root
        parts=name.strip("/").split("/")
        for index,part in enumerate(parts):
            if not SAFE_NAME.fullmatch(part) or part in (".",".."):
                raise ValueError("Unsupported donor path")
            current=current/part
            try:
                st=current.lstat()
            except FileNotFoundError:
                observe(current.parent,current.parent.lstat())
                issues.add("MISSING:"+name)
                return None
            observe(current,st)
            if index<len(parts)-1 and not stat.S_ISDIR(st.st_mode):
                issues.add("PARENT_REVIEW:"+name)
                return None
        return current,st

    def visit(name,depth=0,recursive=False):
        nonlocal total
        if depth>MAX_DEPTH or len(entries)>=MAX_ENTRIES:
            raise ValueError("Legacy inventory entry or depth budget exceeded")
        found=locate(name)
        if found is None:
            return
        p,st=found
        record={"mode":oct(stat.S_IMODE(st.st_mode)),
                "uid":st.st_uid,"gid":st.st_gid}
        if stat.S_ISLNK(st.st_mode):
            target=os.readlink(p)
            record["kind"]="symlink"
            if SAFE_TARGET.fullmatch(target):
                record["target"]=target
            else:
                issues.add("UNSUPPORTED_LINK_TEXT:"+name)
            issues.add("SYMLINK_REVIEW:"+name)
        elif stat.S_ISREG(st.st_mode):
            if st.st_nlink!=1:
                issues.add("HARDLINK_REVIEW:"+name)
                record.update(kind="regular",status="NOT_HASHED_HARDLINK")
            else:
                info,raw=read_file(p,min(MAX_FILE,MAX_TOTAL-total),capture=True)
                total+=info["bytes"]
                record.update(kind="regular",bytes=info["bytes"],sha256=info["sha256"],
                              elf_candidate=raw.startswith(b"\x7fELF"))
        elif stat.S_ISDIR(st.st_mode):
            record["kind"]="directory"
        else:
            record["kind"]="special"
            issues.add("SPECIAL_OBJECT_REVIEW:"+name)
        observe(p,p.lstat())
        entries[name]=record
        if recursive and record["kind"]=="directory":
            # Limit enumeration before materializing or sorting all children.
            children=[]
            with os.scandir(p) as scan:
                for child in scan:
                    if len(children)+len(entries)>=MAX_ENTRIES:
                        raise ValueError("Legacy inventory directory budget exceeded")
                    if not SAFE_NAME.fullmatch(child.name) or child.name in (".",".."):
                        raise ValueError("Unsupported donor entry name")
                    children.append(child.name)
            for child in sorted(children):
                visit(name+"/"+child,depth+1,recursive=True)
            observe(p,p.lstat())
        elif recursive:
            issues.add("TREE_ROOT_REVIEW:"+name)

    observe(root,root.lstat())
    for name in FILES+LINKS:
        visit(name)
        record=entries.get(name)
        if name in FILES and record and record["kind"]!="regular":
            issues.add("CONFIG_OBJECT_REVIEW:"+name)
        if name in LINKS and record and record["kind"]!="symlink":
            issues.add("TOP_LEVEL_LINK_REVIEW:"+name)
    for name in REQUIRED_TREES:
        visit(name,recursive=True)
    for p,mark in watched.items():
        st=p.lstat()
        if fingerprint(st)+(st.st_uid,st.st_gid)!=mark:
            raise ValueError("Donor changed during legacy inventory")
    return {"schema":"r800-tzlite-legacy-scope-v1",
            "status":"LEGACY_SCOPE_REVIEW_REQUIRED" if issues else "LEGACY_SCOPE_INVENTORY_ONLY",
            "problems":sorted(issues),"entries":entries,
            "regular_bytes_hashed":total,
            "elf_candidates":sorted(n for n,v in entries.items() if v.get("elf_candidate")),
            "outside_four_config_baseline":sorted(n for n in entries if entries[n]["kind"]=="regular" and n not in CONFIGS),
            "symlinks_followed":False,"files_copied":False,
            "complete_plugin_inventory_verified":False,"donor_authenticity_verified":False,
            "runtime_verified":False,"safe_to_flash":False}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--root",type=Path,required=True)
    a=p.parse_args()
    try:
        report=inspect(a.root)
    except (OSError,ValueError,RecursionError) as exc:
        report={"schema":"r800-tzlite-legacy-scope-v1","status":"LEGACY_SCOPE_REVIEW_REQUIRED",
                "problems":[str(exc)],"safe_to_flash":False}
    print(json.dumps(report,indent=2,sort_keys=True))
    return 2 if report["problems"] else 0


if __name__=="__main__":
    raise SystemExit(main())
