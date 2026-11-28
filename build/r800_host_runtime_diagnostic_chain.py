#!/usr/bin/env python3
"""Read-only cross-check of saved host runtime diagnostics.

Reports are local unsigned observations, not attestations. No loader or
project import probe is rerun, especially not in a privileged build.
"""
import argparse
import hashlib
import json
from pathlib import Path

from r800_linux_assembly_environment import read_pinned
from r800_linux_host_elf_lock import review_saved as review_elf
from r800_linux_loader_observation import expected_for, LOADER
from r800_python_import_observation import TARGETS, PATHS, tracked_sources
from r800_python_runtime_lock import MAX_FILES, MAX_TOTAL
from r800_stage_adaptation_layer import valid_pin
from r800_extract_super import require
from r800_graphics_donor_binding import checkout_sha

PY_STATUS="SELECTED_PYTHON_RUNTIME_BYTES_AND_ELF_CANDIDATES_ONLY"
FLAGS={"isolated":1,"no_site":1,"ignore_environment":1,"dont_write_bytecode":True}


def scope(report,schema,status,source,lock_pin,false_fields):
    require(isinstance(report,dict) and report.get("schema")==schema and
            report.get("status")==status and report.get("source_sha")==source and
            report.get("environment_lock_sha256")==lock_pin and
            all(report.get(k) is False for k in (*false_fields,"reproducible_build_verified",
                                                "hardware_tested","safe_to_flash")),
            "Unexpected runtime report scope or lock binding")


def review_loader(elf,loader,elf_pin):
    require(loader.get("host_elf_lock_sha256")==elf_pin,"Loader report ELF pin mismatch")
    rows=loader["tools"]
    require(isinstance(rows,dict) and set(rows)==set(elf["roots"]),"Loader tool inventory mismatch")
    for name,row in rows.items():
        require(isinstance(row,dict) and set(row)=={"status","providers","vdso_observed"} and
                isinstance(row["providers"],dict) and type(row["vdso_observed"]) is bool,
                "Invalid loader tool row")
        root=elf["objects"][elf["bindings"][name]]
        expected=expected_for(elf,name)
        if root["interpreter"] is None:
            require(not expected and row=={"status":"NO_INTERPRETER_OR_NEEDED","providers":{},
                                          "vdso_observed":False},"Unexpected static tool row")
            continue
        require(row["status"]=="GLIBC_LIST_MATCH_ONLY","Unexpected loader tool status")
        actual=row["providers"]
        target=elf["bindings"].get(LOADER)
        for label,path in actual.items():
            require(expected.get(label)==path or
                    (label in (LOADER,target) and path==target),"Unexpected saved loader provider")
        for label,path in expected.items():
            require((path==target and label in (LOADER,Path(LOADER).name) and
                     path in actual.values()) or actual.get(label)==path,
                    "Missing saved loader provider")


def review_python(lock,runtime,imports,runtime_pin,sources):
    require(runtime.get("python_version")==lock["python_version"] and
            runtime.get("stdlib_root")=="/usr/lib/python3.12","Python runtime identity mismatch")
    tree=runtime["stdlib"]
    files=tree["files"]
    require(isinstance(files,dict) and 0<len(files)<=MAX_FILES and
            tree["file_count"]==len(files) and tree["problems"]==[],
            "Python runtime inventory review required")
    total=0
    for name,row in files.items():
        require(isinstance(name,str) and not name.startswith("/") and
                "\\" not in name and all(p not in ("",".","..","site-packages","dist-packages")
                                        for p in name.split("/")) and
                isinstance(row,dict) and set(row)=={"kind","bytes","sha256"} and
                row["kind"]=="regular" and type(row["bytes"]) is int and row["bytes"]>=0 and
                valid_pin(row["sha256"]),"Invalid saved Python file identity")
        total+=row["bytes"]
    encoded=json.dumps(files,sort_keys=True,separators=(",",":"),ensure_ascii=True).encode()
    require(total<=MAX_TOTAL and total==tree["regular_bytes"] and
            hashlib.sha256(encoded).hexdigest()==tree["tree_sha256"],"Python tree identity mismatch")
    native=runtime["native_extensions"]
    require(native["status"]=="HOST_STATIC_CANDIDATES_ONLY" and native["problems"]==[] and
            all(native.get(k) is False for k in ("loader_search_verified","runtime_verified",
                                                 "host_isolated","safe_to_flash")),
            "Python native extensions require review")
    for name,row in files.items():
        if name.endswith(".so"):
            path=str(Path(runtime["stdlib_root"])/name)
            obj=native["objects"].get(path,{})
            require(native["bindings"].get(name)==path and
                    all(obj.get(k)==row[k] for k in ("bytes","sha256")),
                    "Python native extension root mismatch")
    require(imports.get("python_runtime_lock_sha256")==runtime_pin and
            imports.get("runtime_inventory_status")==PY_STATUS and
            imports.get("targets")==list(TARGETS) and imports.get("flags")==FLAGS and
            imports.get("sys_path")==PATHS,"Python import report binding mismatch")
    modules=imports["modules"]
    require(isinstance(modules,dict) and 0<len(modules)<=1024 and
            not set(modules)&{"site","sitecustomize","usercustomize"} and
            all(modules.get(n,{}).get("kind")=="tracked_source" for n in TARGETS),
            "Python import inventory mismatch")
    for name,row in modules.items():
        kind=row.get("kind")
        if kind in ("built-in","frozen"):
            require(set(row)=={"kind"},"Invalid built-in module record")
        elif kind=="tracked_source":
            require(set(row)=={"kind","sha256"} and name in sources and
                    row["sha256"]==sources[name]["sha256"],"Tracked Python source pin mismatch")
        else:
            require(kind=="stdlib" and set(row)=={"kind","path","sha256","cached_candidate_sha256"},
                    "Unexpected Python module origin")
            pin=files.get(row["path"],{}).get("sha256")
            require(pin is not None and row["sha256"]==pin,"Python module source pin mismatch")
            cache=row["cached_candidate_sha256"]
            if cache is not None:
                # The observation records a candidate hash, not the actual cache read.
                require(any(r["sha256"]==cache and p.endswith(".pyc") for p,r in files.items()),
                        "Unknown Python bytecode candidate")


def review(lock,elf,loader,runtime,imports,pins,source_sha,sources):
    review_elf(lock,elf,pins["lock"],source_sha)
    scope(loader,"galwear-r800-linux-loader-observation-v1",
          "GLIBC_LIST_SELECTED_PROVIDERS_MATCH_ONLY",source_sha,pins["lock"],
          ("normal_execution_verified","secure_execution_verified","dlopen_coverage_verified",
           "python_extensions_verified"))
    scope(runtime,"galwear-r800-python-runtime-lock-v1",PY_STATUS,source_sha,pins["lock"],
          ("actual_import_resolution_verified","third_party_packages_verified","dlopen_coverage_verified"))
    scope(imports,"galwear-r800-python-import-observation-v1","ISOLATED_IMPORT_ORIGINS_MATCH_ONLY",
          source_sha,pins["lock"],("assembly_executed","all_runtime_imports_verified",
                                  "dlopen_coverage_verified"))
    review_loader(elf,loader,pins["elf"])
    review_python(lock,runtime,imports,pins["runtime"],sources)
    return {"schema":"galwear-r800-host-runtime-diagnostic-chain-v1","source_sha":source_sha,
            "status":"SAVED_HOST_RUNTIME_DIAGNOSTIC_CHAIN_ONLY","report_sha256":pins,
            "loader_tool_count":len(loader["tools"]),"python_module_count":len(imports["modules"]),
            "live_runtime_verified":False,"assembly_executed":False,"reproducible_build_verified":False,
            "hardware_tested":False,"safe_to_flash":False}


def check(bundle,source_sha):
    checkout_sha(source_sha)
    require(set(bundle)=={"lock","elf","loader","runtime","imports"} and
            len({Path(v[0]) for v in bundle.values()})==5,"Distinct complete runtime evidence required")
    rows={n:read_pinned(*v) for n,v in bundle.items()}
    pins={n:v[1] for n,v in bundle.items()}
    sources=tracked_sources()
    result=review(*(rows[n][1] for n in ("lock","elf","loader","runtime","imports")),
                  pins,source_sha,sources)
    require(tracked_sources()==sources and
            all(read_pinned(*v)[0]==rows[n][0] for n,v in bundle.items()),"Runtime evidence changed")
    checkout_sha(source_sha)
    return result


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ("lock","elf","loader","runtime","imports"):
        p.add_argument("--"+name,required=True,type=Path)
        p.add_argument("--"+name+"-sha256",required=True)
    p.add_argument("--source-sha",required=True)
    a=p.parse_args()
    bundle={n:(getattr(a,n),getattr(a,n+"_sha256")) for n in
            ("lock","elf","loader","runtime","imports")}
    print(json.dumps(check(bundle,a.source_sha),indent=2,sort_keys=True))


if __name__=="__main__":
    main()
