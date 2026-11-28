#!/usr/bin/env python3
"""Explicit import-only observation in a trusted, isolated Python child.

Imports reviewed same-head project modules; does not invoke build entrypoints.
Not a sandbox or proof of all imports made by a real assembly.
"""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys

from r800_linux_assembly_environment import read_pinned
from r800_python_runtime_lock import verify as verify_runtime, file_pin
from r800_extract_super import require
from r800_graphics_donor_binding import checkout_sha

REPO=Path(__file__).resolve().parents[1]
ROOT=Path("/usr/lib/python3.12")
PATHS=["/usr/lib/python312.zip",str(ROOT),str(ROOT/"lib-dynload")]
TARGETS=("r800_donor_manager","r800_build_local_development","r800_development_readiness")
ENV={"PATH":"/usr/sbin:/usr/bin:/sbin:/bin","LC_ALL":"C","TZ":"UTC"}
MAX_MODULES=1024
MAX_SOURCES=1024
MAX_OUTPUT=1024*1024
NAME=re.compile(r"[A-Za-z_][A-Za-z0-9_]*")

CHILD=r'''
import sys, json, hashlib, importlib, importlib.abc, importlib.util
from pathlib import Path
cfg=json.load(sys.stdin)
def check(test,message):
    if not test:
        raise RuntimeError(message)
def flags():
    return {"isolated":sys.flags.isolated,"no_site":sys.flags.no_site,
            "ignore_environment":sys.flags.ignore_environment,
            "dont_write_bytecode":sys.dont_write_bytecode}
initial=list(sys.path)
check(initial==cfg["paths"],"Unexpected isolated sys.path")
check(flags()=={"isolated":1,"no_site":1,"ignore_environment":1,
               "dont_write_bytecode":True},"Unexpected isolated Python flags")
class TrackedSource(importlib.abc.Loader):
    def __init__(self,row):
        self.row=row
    def create_module(self,spec):
        return None
    def exec_module(self,module):
        path=Path(self.row["path"])
        check(path.resolve(strict=True)==path,"Noncanonical tracked source")
        raw=path.read_bytes()
        check(len(raw)==self.row["bytes"] and
              hashlib.sha256(raw).hexdigest()==self.row["sha256"],
              "Tracked source pin mismatch")
        exec(compile(raw,str(path),"exec"),module.__dict__)
class TrackedFinder(importlib.abc.MetaPathFinder):
    def find_spec(self,fullname,path=None,target=None):
        if path is not None or fullname not in cfg["sources"]:
            return None
        row=cfg["sources"][fullname]
        return importlib.util.spec_from_file_location(fullname,row["path"],
                                                     loader=TrackedSource(row))
sys.meta_path.append(TrackedFinder())
for name in cfg["targets"]:
    importlib.import_module(name)
rows={}
for name,module in sorted(sys.modules.items()):
    if name=="__main__":
        continue
    if module is None:
        raise RuntimeError("Null module: "+name)
    spec=getattr(module,"__spec__",None)
    rows[name]={"origin":None if spec is None else spec.origin,
                "cached":getattr(module,"__cached__",None)}
print(json.dumps({"flags":flags(),"initial_path":initial,"final_path":list(sys.path),
                  "modules":rows},sort_keys=True))
'''


def tracked_sources():
    raw=subprocess.check_output(["git","-C",str(REPO),"ls-files","-z","--","build"],
                                env=ENV,timeout=30)
    sources={}
    for value in raw.decode("utf-8").split("\0"):
        p=Path(value)
        if p.parent!=Path("build") or p.suffix!=".py":
            continue
        require(NAME.fullmatch(p.stem),"Unsupported tracked module name")
        path=REPO/p
        require(path.resolve(strict=True)==path,"Noncanonical tracked Python source")
        sources[p.stem]={"path":str(path),**file_pin(path)}
    require(0<len(sources)<=MAX_SOURCES and all(n in sources for n in TARGETS),
            "Incomplete tracked source inventory")
    return sources


def review(observed,sources,runtime):
    require(observed["flags"]=={"isolated":1,"no_site":1,"ignore_environment":1,
                                "dont_write_bytecode":True} and
            observed["initial_path"]==PATHS and observed["final_path"]==PATHS,
            "Unexpected isolated Python path or flags")
    rows=observed["modules"]
    require(isinstance(rows,dict) and 0<len(rows)<=MAX_MODULES and
            all(n in rows for n in TARGETS),"Incomplete import observation")
    require(not set(rows)&{"site","sitecustomize","usercustomize"},
            "Unexpected site initialization")
    files=runtime["stdlib"]["files"]
    result={}
    for name,row in rows.items():
        require(isinstance(row,dict) and set(row)=={"origin","cached"},"Unexpected module record")
        origin=row["origin"]
        if origin in ("built-in","frozen"):
            require(name not in TARGETS,"Unexpected target origin")
            result[name]={"kind":origin}
            continue
        require(isinstance(origin,str),"Namespace or missing module origin requires review")
        if name in sources and origin==sources[name]["path"]:
            # The custom source loader bypasses cached bytecode.
            result[name]={"kind":"tracked_source","sha256":sources[name]["sha256"]}
            continue
        path=Path(origin)
        require(path.is_absolute() and path.is_relative_to(ROOT) and
                str(path)==origin and ".." not in path.parts,
                "Unexpected external module origin: "+name)
        key=path.relative_to(ROOT).as_posix()
        pinned=files.get(key,{})
        require(pinned.get("kind")=="regular","Module origin not pinned: "+name)
        cached=row["cached"]
        cache_pin=None
        if cached is not None:
            c=Path(cached)
            require(c.is_absolute() and c.is_relative_to(ROOT) and str(c)==cached and
                    ".." not in c.parts,"Unexpected bytecode cache path")
            candidate=files.get(c.relative_to(ROOT).as_posix())
            if candidate is not None:
                require(candidate["kind"]=="regular","Bytecode cache not regular")
                cache_pin=candidate["sha256"]
            else:
                require(not c.exists() and not c.is_symlink(),"Unpinned bytecode cache")
        result[name]={"kind":"stdlib","path":key,"sha256":pinned["sha256"],
                      "cached_candidate_sha256":cache_pin}
    require(all(result[n]["kind"]=="tracked_source" for n in TARGETS),
            "Build entrypoints must resolve to tracked sources")
    return result


def observe(lock_path,lock_pin,runtime_path,runtime_pin,source_sha):
    checkout_sha(source_sha)
    require(sys.dont_write_bytecode,"Use Python -B")
    require(os.environ.get("PATH")==ENV["PATH"],"Set documented system PATH")
    require(os.geteuid()!=0,"Run import observation unprivileged in a trusted VM")
    require(not Path(PATHS[0]).exists() and not Path(PATHS[0]).is_symlink(),
            "Python zip import path requires review")
    _,lock=read_pinned(lock_path,lock_pin)
    runtime=verify_runtime(lock_path,lock_pin,runtime_path,runtime_pin,source_sha)
    sources=tracked_sources()
    config={"paths":PATHS,"targets":TARGETS,"sources":sources}
    python=lock["tools"]["python3"]["resolved"]
    child=subprocess.run([python,"-I","-S","-B","-c",CHILD],input=json.dumps(config),
                         env=ENV,text=True,capture_output=True,timeout=60,check=True)
    require(not child.stderr.strip() and len(child.stdout)<=MAX_OUTPUT,
            "Unexpected import diagnostics or output budget exceeded")
    observed=json.loads(child.stdout)
    rows=review(observed,sources,runtime)
    require(tracked_sources()==sources and
            verify_runtime(lock_path,lock_pin,runtime_path,runtime_pin,source_sha)==runtime,
            "Python or tracked source inventory changed")
    checkout_sha(source_sha)
    return {"schema":"galwear-r800-python-import-observation-v1",
            "source_sha":source_sha,"environment_lock_sha256":lock_pin,
            "python_runtime_lock_sha256":runtime_pin,"status":"ISOLATED_IMPORT_ORIGINS_MATCH_ONLY",
            "targets":list(TARGETS),"flags":observed["flags"],"sys_path":PATHS,
            "modules":rows,"runtime_inventory_status":runtime["status"],
            "assembly_executed":False,"all_runtime_imports_verified":False,
            "dlopen_coverage_verified":False,"reproducible_build_verified":False,
            "hardware_tested":False,"safe_to_flash":False}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--lock",required=True,type=Path)
    p.add_argument("--lock-sha256",required=True)
    p.add_argument("--runtime",required=True,type=Path)
    p.add_argument("--runtime-sha256",required=True)
    p.add_argument("--source-sha",required=True)
    p.add_argument("--confirm-trusted-vm",required=True,action="store_true")
    a=p.parse_args()
    print(json.dumps(observe(a.lock,a.lock_sha256,a.runtime,a.runtime_sha256,a.source_sha),
                     indent=2,sort_keys=True))


if __name__=="__main__":
    main()
