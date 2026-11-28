#!/usr/bin/env python3
"""Bounded userspace entry observations, never a daemon/hardware acceptance test.

Use trusted local donor files only, on a disposable unprivileged Linux host.
Each target gets a fresh network/PID namespace and empty temporary state.
No real /dev, /sys, GNSS NV data or writable host directory is exposed.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

from r800_runtime_loader_qemu import (source_rows, sha, limits, REFERENCE, LOCAL,
                                     BRIDGE, LOADER, SEARCH, MAX_LOG, MAX_TOTAL)
from r800_tizen_config_layout import CONFIGS, PREFIX, MAX_CONFIG, inspect_config
from r800_stage_adaptation_layer import valid_pin, MAX_FILE
from r800_android_userspace_preflight import read_regular
from r800_graphics_donor_binding import checkout_sha
from r800_verify_tizen_stage import unique_keys
from r800_extract_super import require

LOCAL_COMMANDS={
    "/usr/bin/lhd": ["/etc/lhd/lhd.conf"],
    "/usr/bin/gpsd": ["-c","/etc/gps-manager/brcm/gpsd.xml"],
    "/usr/bin/sensord": [],
}
MAX_REPORT=16*1024**2


def classify(scope, target, rc, raw):
    require(len(raw)<=MAX_LOG,"Startup transcript exceeds budget")
    if scope==REFERENCE:
        require(target==BRIDGE and rc==1 and raw.startswith(b"dlopen: ") and
                b"libbrcm.so" in raw and b"No such file or directory" in raw and
                len(raw.splitlines())==1,
                "Reference must reach expected missing libbrcm failure")
        return "REFERENCE_EXPECTED_MISSING_LIBBRCM"
    # Exit or survival for a few seconds is not proof of readiness.
    if rc in (124,137):
        return "BOUNDED_TIMEOUT_REVIEW"
    if rc==0:
        return "EXIT_ZERO_REVIEW"
    return "NONZERO_EXIT_REVIEW"


def loader_report(path,pin,runtime_pin,scope,source_sha,targets):
    raw=read_regular(path,MAX_REPORT)
    require(valid_pin(pin) and sha(raw)==pin,"Loader report pin mismatch")
    report=json.loads(raw,object_pairs_hook=unique_keys)
    require(report.get("schema")=="galwear-r800-loader-qemu-v1" and
            report.get("status")=="ARM32_LOADER_LIST_PASS" and
            report.get("source_sha")==source_sha and report.get("scope")==scope and
            report.get("runtime_evidence_sha256")==runtime_pin and
            report.get("safe_to_flash") is False and set(report.get("checks",{}))==set(targets) and
            all(row.get("exit_code")==0 for row in report["checks"].values()),
            "Same-runtime successful loader evidence required")
    return raw,report


def run(root,pin,scope,loader,loader_pin,output,source_sha):
    checkout_sha(source_sha)
    require(scope in (REFERENCE,LOCAL),"Unknown probe scope")
    require(os.geteuid()!=0,"Run startup probe unprivileged")
    root,loader,output=(Path(p).absolute() for p in (root,loader,output))
    repo=Path(__file__).resolve().parents[1]
    require(root.resolve(strict=True)==root and root.is_dir() and loader.resolve(strict=True)==loader,
            "Canonical local inputs required")
    require(not output.exists() and not output.is_symlink() and
            not any(output.resolve().is_relative_to(p) for p in (repo,root)),
            "Fresh report outside input trees required")
    name,original,rows,targets=source_rows(root,pin,scope,source_sha)
    loader_raw,prior=loader_report(loader,loader_pin,pin,scope,source_sha,targets)
    tools={}
    for tool in ("qemu-arm-static","bwrap","timeout"):
        path=shutil.which(tool)
        require(path,"Missing isolation tool: "+tool)
        p=Path(path).resolve(strict=True)
        tools[tool]=(p,sha(read_regular(p,128*1024**2)))
    require(prior["tool_sha256"]=={n:h for n,(_,h) in tools.items()},"Isolation tool identity differs")
    if scope==LOCAL:
        manifest=json.loads(original,object_pairs_hook=unique_keys)
        configs={}
        for path in CONFIGS:
            rel=PREFIX+path
            require(rel in manifest["files"],"Selected Tizen configuration missing")
            row=manifest["files"][rel]
            raw=read_regular(root/rel,MAX_CONFIG)
            configs[path]=raw
            require(row["bytes"]==len(raw) and row["sha256"]==sha(raw),"Tizen config changed")
            rows[path]=(rel,row)
        inspect_config(configs)
    commands={BRIDGE:["0"]} if scope==REFERENCE else LOCAL_COMMANDS
    require(set(commands)<=set(targets),"Startup target missing from loader report")
    with tempfile.TemporaryDirectory(prefix="r800-entry-probe-") as tmp:
        work=Path(tmp)
        guest=work/"root"
        guest.mkdir()
        inventory={}
        total=0
        for path,(rel,row) in sorted(rows.items()):
            raw=read_regular(root/rel,MAX_FILE)
            total+=len(raw)
            require(total<=MAX_TOTAL and len(raw)==row["bytes"] and sha(raw)==row["sha256"],
                    "Runtime member mismatch: "+rel)
            dest=guest/path.lstrip("/")
            dest.parent.mkdir(parents=True,exist_ok=True)
            with dest.open("xb") as stream:
                stream.write(raw)
            dest.chmod(0o555 if path==LOADER or path in commands else 0o444)
            inventory[path]=row["sha256"]
        for n in ("dev","proc","sys","tmp","run","mnt","opt/gnss"):
            (guest/n).mkdir(parents=True,exist_ok=True)
        (guest/"qemu").touch()
        command=[str(tools["timeout"][0]),"-k","2s","8s",str(tools["bwrap"][0]),
                 "--unshare-all","--die-with-parent","--new-session","--clearenv",
                 "--ro-bind",str(guest),"/","--ro-bind",str(tools["qemu-arm-static"][0]),"/qemu",
                 "--dev","/dev","--proc","/proc","--tmpfs","/tmp","--tmpfs","/run",
                 "--tmpfs","/mnt","--tmpfs","/opt/gnss","--chdir","/",
                 "/qemu","-cpu","cortex-a15","-L","/","-E","LD_LIBRARY_PATH="+SEARCH]
        observations={}
        for target,args in commands.items():
            logfile=work/"entry.log"
            with logfile.open("wb") as stream:
                proc=subprocess.run(command+[target,*args],stdout=stream,stderr=subprocess.STDOUT,
                                    env={"LC_ALL":"C","PATH":"/usr/bin:/bin"},preexec_fn=limits,timeout=15)
            with logfile.open("rb") as stream:
                raw=stream.read(MAX_LOG+1)
            require(not raw.startswith(b"bwrap:") and not raw.startswith(b"timeout:"),
                    "Isolation command failed")
            observations[target]={"classification":classify(scope,target,proc.returncode,raw),
                                  "exit_code":proc.returncode,"log_sha256":sha(raw),"log_bytes":len(raw)}
        for path,(rel,row) in rows.items():
            require(sha(read_regular(root/rel,MAX_FILE))==
                    sha(read_regular(guest/path.lstrip("/"),MAX_FILE))==inventory[path],
                    "Runtime member changed")
        require(read_regular(root/name,MAX_REPORT)==original and read_regular(loader,MAX_REPORT)==loader_raw,
                "Input evidence changed")
        require(all(sha(read_regular(p,128*1024**2))==h for p,h in tools.values()),"Tool changed")
        checkout_sha(source_sha)
        result={"schema":"galwear-r800-runtime-entry-qemu-v1",
                "status":"REFERENCE_NEGATIVE_ENTRY_PASS" if scope==REFERENCE else "LOCAL_STARTUP_OBSERVATIONS_ONLY",
                "scope":scope,"source_sha":source_sha,"runtime_evidence_sha256":pin,
                "loader_evidence_sha256":loader_pin,"observations":observations,
                "daemon_startup_verified":False,"dlopen_runtime_verified":False,
                "gnss_runtime_verified":False,"hardware_tested":False,"safe_to_flash":False}
        with output.open("x",encoding="utf-8") as stream:
            json.dump(result,stream,indent=2,sort_keys=True)
            stream.write("\n")
    return result


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ("runtime","loader","output"):
        p.add_argument("--"+name,type=Path,required=True)
    for name in ("runtime-sha256","loader-sha256","source-sha"):
        p.add_argument("--"+name,required=True)
    p.add_argument("--scope",choices=(REFERENCE,LOCAL),required=True)
    a=p.parse_args()
    print(run(a.runtime,a.runtime_sha256,a.scope,a.loader,a.loader_sha256,a.output,a.source_sha)["status"])


if __name__=="__main__":
    main()
