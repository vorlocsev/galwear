#!/usr/bin/env python3
"""Isolated ARM32 glibc loader --list probe for a trusted staged runtime.

No normal daemon startup, hardware access, plugin constructors or GNSS
acceptance is claimed. Run only as an unprivileged user on a disposable host.
The reference profile is never identified as Tizen.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import shutil
import subprocess
import tempfile

from r800_android_userspace_preflight import read_regular
from r800_android_linker_audit import inspect
from r800_graphics_donor_binding import checkout_sha
from r800_stage_adaptation_layer import load, valid_pin, MAX_FILE
from r800_tizen_config_layout import PREFIX
from r800_verify_tizen_stage import unique_keys, guest_name
from r800_gps_donor_snapshot import DONORS
from r800_extract_super import require

MAX_LOG=1024**2
MAX_TOTAL=512*1024**2
REFERENCE="DEBIAN_REFERENCE_NOT_TIZEN"
LOCAL="LOCAL_TIZEN_CANDIDATE"
BRIDGE="/opt/usr/r800dev/gpsbridge"
LOADER="/lib/ld-linux.so.3"
SEARCH="/lib:/usr/lib:/usr/lib/sensor"


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def transcript(raw, rc, inventory, needed):
    require(rc==0,"Loader probe failed or timed out")
    require(0<len(raw)<=MAX_LOG,"Invalid loader transcript size")
    found={}
    for line in raw.decode("utf-8").splitlines():
        line=line.strip()
        virtual=re.fullmatch(r"(linux-vdso\.so\.1|linux-gate\.so\.1)\s+\(0x[0-9a-fA-F]+\)",line)
        if virtual:
            continue
        row=re.fullmatch(r"([A-Za-z0-9_.+-]+)\s+=>\s+(/[A-Za-z0-9_./+-]+)\s+\(0x[0-9a-fA-F]+\)",line)
        direct=re.fullmatch(r"(/[A-Za-z0-9_./+-]+)\s+\(0x[0-9a-fA-F]+\)",line)
        require(row or direct,"Unexpected or unresolved loader output: "+line[:200])
        path=row[2] if row else direct[1]
        name=row[1] if row else Path(path).name
        require(path in inventory and Path(path).name==name and name not in found,
                "Unexpected or duplicate resolved library: "+name)
        found[name]={"path":path,"sha256":inventory[path]}
    require(set(needed)<=set(found),"Missing direct DT_NEEDED resolution")
    return found


def source_rows(root, pin, scope, source_sha):
    name="runtime-layer-evidence.json" if scope==REFERENCE else "tizen-runtime-evidence.json"
    raw=read_regular(root/name,16*1024**2)
    require(valid_pin(pin) and sha(raw)==pin,"Runtime evidence pin mismatch")
    report=json.loads(raw,object_pairs_hook=unique_keys)
    require(report.get("source_sha")==source_sha and report.get("safe_to_flash") is False,
            "Runtime source or scope mismatch")
    if scope==REFERENCE:
        require(report.get("schema")=="galwear-r800-runtime-layer-v1" and
                report.get("status")=="GPS_RUNTIME_SUBSET_STAGED_ONLY" and report.get("scope")==REFERENCE,
                "Expected Debian reference runtime")
        base="reference-runtime/"
        require(set(report["files"])=={base+"gpsbridge",*(base+"lib/"+n for n in DONORS)},
                "Unexpected reference inventory")
        rows={LOADER if n==base+"lib/ld-linux.so.3" else
              "/"+n.removeprefix(base) if n!=base+"gpsbridge" else BRIDGE:(n,r)
              for n,r in report["files"].items()}
        targets=[BRIDGE]
    else:
        verified,_=load(root,name,pin,source_sha,True)
        require(verified==report,"Runtime evidence changed")
        rows={}
        for n,r in report["files"].items():
            if n=="r800dev/gpsbridge":
                rows[BRIDGE]=(n,r)
            elif n.startswith(PREFIX+"/"):
                guest=n.removeprefix(PREFIX)
                if guest.startswith(("/lib/","/usr/lib/","/usr/bin/","/bin/")):
                    guest_name(guest)
                    rows[guest]=(n,r)
        targets=["/usr/bin/lhd","/usr/bin/gpsd","/usr/bin/sensord","/usr/bin/sensorctl",BRIDGE]
        targets.extend(sorted(report.get("selected_plugins",{})))
    require(LOADER in rows and set(targets)<=set(rows),"Missing loader or target")
    return name,raw,rows,targets


def limits():
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    resource.setrlimit(resource.RLIMIT_FSIZE,(MAX_LOG,MAX_LOG))
    resource.setrlimit(resource.RLIMIT_CPU,(20,20))


def run(root, pin, scope, output, source_sha):
    checkout_sha(source_sha)
    require(scope in (REFERENCE,LOCAL),"Unknown probe scope")
    require(os.geteuid()!=0,"Run QEMU probe as an unprivileged user")
    root=Path(root).absolute()
    output=Path(output).absolute()
    repo=Path(__file__).resolve().parents[1]
    require(root.resolve(strict=True)==root and root.is_dir(),"Canonical runtime directory required")
    require(not output.exists() and not output.is_symlink() and
            not any(output.resolve().is_relative_to(p) for p in (root,repo)),
            "Fresh report outside input trees required")
    tools={}
    for tool in ("qemu-arm-static","bwrap","timeout"):
        path=shutil.which(tool)
        require(path,"Missing isolation tool: "+tool)
        p=Path(path).resolve(strict=True)
        tools[tool]=(p,sha(read_regular(p,128*1024**2)))
    name,original,rows,targets=source_rows(root,pin,scope,source_sha)
    with tempfile.TemporaryDirectory(prefix="r800-loader-probe-") as tmp:
        work=Path(tmp)
        guest=work/"root"
        guest.mkdir()
        inventory={}
        total=0
        for path,(relative,row) in sorted(rows.items()):
            raw=read_regular(root/relative,MAX_FILE)
            total+=len(raw)
            require(total<=MAX_TOTAL and len(raw)==row["bytes"] and sha(raw)==row["sha256"],
                    "Runtime member mismatch: "+relative)
            dest=guest/path.lstrip("/")
            dest.parent.mkdir(parents=True,exist_ok=True)
            with dest.open("xb") as stream:
                stream.write(raw)
            dest.chmod(0o555 if path==LOADER or path in targets else 0o444)
            inventory[path]=row["sha256"]
        for n in ("dev","proc"):
            (guest/n).mkdir()
        (guest/"qemu").touch()
        command=[str(tools["timeout"][0]),"-k","5s","25s",str(tools["bwrap"][0]),
                 "--unshare-all","--die-with-parent","--new-session","--clearenv",
                 "--ro-bind",str(guest),"/","--ro-bind",str(tools["qemu-arm-static"][0]),"/qemu",
                 "--dev","/dev","--proc","/proc","--chdir","/",
                 "/qemu","-cpu","cortex-a15","-L","/"]
        checks={}
        for target in targets:
            info=inspect(read_regular(guest/target.lstrip("/"),MAX_FILE))
            require(info["abi"]=="arm" and info["has_dynamic"],"Expected ARM32 dynamic target")
            logfile=work/"loader.log"
            with logfile.open("wb") as stream:
                proc=subprocess.run(command+[LOADER,"--inhibit-cache","--library-path",SEARCH,
                                              "--list",target],
                                    stdout=stream,stderr=subprocess.STDOUT,
                                    env={"LC_ALL":"C","PATH":"/usr/bin:/bin"},preexec_fn=limits,
                                    timeout=35)
            raw=read_regular(logfile,MAX_LOG)
            found=transcript(raw,proc.returncode,inventory,info["needed"])
            checks[target]={"resolved":found,"log_sha256":sha(raw),"exit_code":proc.returncode}
        for path,(relative,row) in rows.items():
            require(sha(read_regular(root/relative,MAX_FILE))==
                    sha(read_regular(guest/path.lstrip("/"),MAX_FILE))==inventory[path],
                    "Runtime member changed")
        require(read_regular(root/name,16*1024**2)==original,"Runtime evidence changed")
        require(all(sha(read_regular(p,128*1024**2))==h for p,h in tools.values()),
                "Isolation tool changed")
        checkout_sha(source_sha)
        result={"schema":"galwear-r800-loader-qemu-v1","status":"ARM32_LOADER_LIST_PASS",
                "scope":scope,"source_sha":source_sha,"runtime_evidence_sha256":pin,
                "tool_sha256":{n:h for n,(_,h) in tools.items()},"checks":checks,
                "daemon_startup_verified":False,"dlopen_runtime_verified":False,
                "gnss_runtime_verified":False,"hardware_tested":False,"safe_to_flash":False}
        with output.open("x",encoding="utf-8") as stream:
            json.dump(result,stream,indent=2,sort_keys=True)
            stream.write("\n")
    return result


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--runtime",type=Path,required=True)
    p.add_argument("--runtime-sha256",required=True)
    p.add_argument("--scope",choices=(REFERENCE,LOCAL),required=True)
    p.add_argument("--output",type=Path,required=True)
    p.add_argument("--source-sha",required=True)
    a=p.parse_args()
    print(run(a.runtime,a.runtime_sha256,a.scope,a.output,a.source_sha)["status"])


if __name__=="__main__":
    main()
