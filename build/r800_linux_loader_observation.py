#!/usr/bin/env python3
"""Explicit trusted-VM glibc --list observation of pinned host executables.

Not a sandbox. Never use on donors, guest executables or untrusted libraries.
The dynamic loader may map host code; this is not ordinary tool execution,
secure-execution emulation, or a full runtime dependency trace.
"""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess

from r800_linux_assembly_environment import read_pinned
from r800_linux_host_elf_lock import verify as verify_elf, review_saved
from r800_gps_host_elf import LOADER, LIMIT, NAME
from r800_donor_preflight import digest
from r800_extract_super import require
from r800_graphics_donor_binding import checkout_sha

ENV={"PATH":"/usr/sbin:/usr/bin:/sbin:/bin","LC_ALL":"C","TZ":"UTC"}
CACHE=Path("/etc/ld.so.cache")
PRELOAD=Path("/etc/ld.so.preload")
MAX_OUTPUT=1024*1024
ADDRESS=r"\s+\(0x[0-9a-fA-F]+\)\s*$"
PATH=r"/[A-Za-z0-9_./+@-]+"
MAPPED=re.compile(r"^\s*([A-Za-z0-9_.+-]+)\s+=>\s+("+PATH+")"+ADDRESS)
DIRECT=re.compile(r"^\s*("+PATH+")"+ADDRESS)
VDSO=re.compile(r"^\s*linux-vdso\.so\.1"+ADDRESS)


def configuration():
    # The system-wide preload file is not overridden by a clean environment.
    require(not PRELOAD.is_symlink(),"Host preload symlink requires review")
    if PRELOAD.exists():
        require(PRELOAD.is_file() and PRELOAD.stat().st_size==0,
                "Nonempty system-wide preload requires review")
    require(not CACHE.is_symlink(),"Host loader cache symlink requires review")
    return {"cache":digest(CACHE,16*1024**2) if CACHE.exists() else None,
            "preload":"EMPTY" if PRELOAD.exists() else "ABSENT"}


def expected_for(report,name):
    objects,bindings=report["objects"],report["bindings"]
    root=bindings[name]
    seen=set()
    needed={}
    pending=[root]
    while pending:
        path=pending.pop()
        if path in seen:
            continue
        seen.add(path)
        row=objects[path]
        for label in row["needed"]+([LOADER] if row["interpreter"] else []):
            provider=bindings[label]
            needed[label]=provider
            pending.append(provider)
    return needed


def parse_listing(output):
    require(isinstance(output,str) and len(output)<=MAX_OUTPUT,"Loader output exceeds budget")
    rows={}
    vdso=False
    for line in output.splitlines():
        if not line.strip():
            continue
        if VDSO.fullmatch(line):
            require(not vdso,"Duplicate virtual DSO")
            vdso=True
            continue
        match=MAPPED.fullmatch(line)
        if match:
            name,path=match.groups()
            require(NAME.fullmatch(name) and name not in (".",".."),"Invalid loader dependency name")
        else:
            match=DIRECT.fullmatch(line)
            require(match is not None,"Unexpected or unresolved loader listing")
            name=path=match[1]
        require(name not in rows,"Duplicate loader dependency name")
        rows[name]=path
    return rows,vdso


def compare_listing(report,name,output,resolve=None):
    if resolve is None:
        resolve=lambda p:str(Path(p).resolve(strict=True))
    expected=expected_for(report,name)
    observed,vdso=parse_listing(output)
    objects=report["objects"]
    loader=report["bindings"].get(LOADER)
    resolved={}
    for label,path in observed.items():
        target=resolve(path)
        require(target in objects,"Loader selected unpinned object")
        if label.startswith("/"):
            require(target==loader and label in (LOADER,loader),
                    "Unexpected direct loader object")
        else:
            require(expected.get(label)==target,"Loader provider differs from static candidate")
        resolved[label]=target
    for label,target in expected.items():
        if label==LOADER or (target==loader and label==Path(LOADER).name):
            require(any(v==target for v in resolved.values()),"Expected loader not observed")
        else:
            require(resolved.get(label)==target,"Expected dependency not observed: "+label)
    return {"providers":dict(sorted(resolved.items())),"vdso_observed":vdso}


def observe(lock_path,lock_pin,elf_path,elf_pin,source_sha):
    checkout_sha(source_sha)
    require(os.environ.get("PATH")==ENV["PATH"],"Set documented system PATH")
    require(os.geteuid()!=0,"Run loader observation as an unprivileged user in a trusted VM")
    _,lock=read_pinned(lock_path,lock_pin)
    static=verify_elf(lock_path,lock_pin,elf_path,elf_pin,source_sha)
    review_saved(lock,static,lock_pin,source_sha)
    config=configuration()
    loader=static["bindings"].get(LOADER)
    require(loader is not None and str(Path(LOADER).resolve(strict=True))==loader,
            "Pinned glibc loader required")
    objects=static["objects"]
    def rehash():
        for path,row in objects.items():
            p=Path(path)
            require(p.resolve(strict=True)==p and digest(p,LIMIT)=={
                    "bytes":row["bytes"],"sha256":row["sha256"]},"Pinned host ELF object changed")
    rehash()
    rows={}
    for name in static["roots"]:
        root=static["bindings"][name]
        row=objects[root]
        if row["interpreter"] is None:
            require(not row["needed"],"Non-interpreted dynamic executable requires review")
            rows[name]={"status":"NO_INTERPRETER_OR_NEEDED","providers":{},"vdso_observed":False}
            continue
        require(row["interpreter"]==LOADER,"Unexpected interpreter")
        result=subprocess.run([loader,"--list",root],env=ENV,stdin=subprocess.DEVNULL,
                              capture_output=True,text=True,encoding="utf-8",timeout=30,check=True)
        require(not result.stderr.strip(),"Loader emitted diagnostics")
        rows[name]={"status":"GLIBC_LIST_MATCH_ONLY",**compare_listing(static,name,result.stdout)}
    rehash()
    require(configuration()==config,"Host loader configuration changed")
    require(verify_elf(lock_path,lock_pin,elf_path,elf_pin,source_sha)==static,
            "Static ELF evidence changed")
    checkout_sha(source_sha)
    return {"schema":"galwear-r800-linux-loader-observation-v1",
            "source_sha":source_sha,"environment_lock_sha256":lock_pin,"host_elf_lock_sha256":elf_pin,
            "status":"GLIBC_LIST_SELECTED_PROVIDERS_MATCH_ONLY","configuration":config,"tools":rows,
            "normal_execution_verified":False,"secure_execution_verified":False,
            "dlopen_coverage_verified":False,"python_extensions_verified":False,
            "reproducible_build_verified":False,"hardware_tested":False,"safe_to_flash":False}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--lock",required=True,type=Path)
    p.add_argument("--lock-sha256",required=True)
    p.add_argument("--elf",required=True,type=Path)
    p.add_argument("--elf-sha256",required=True)
    p.add_argument("--source-sha",required=True)
    p.add_argument("--confirm-trusted-vm",required=True,action="store_true")
    a=p.parse_args()
    result=observe(a.lock,a.lock_sha256,a.elf,a.elf_sha256,a.source_sha)
    print(json.dumps(result,indent=2,sort_keys=True))


if __name__=="__main__":
    main()
