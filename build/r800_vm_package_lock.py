#!/usr/bin/env python3
"""Read-only dpkg package inventory for the candidate dedicated build VM.

No apt update/install, VM deployment, disk access, or guest execution.
Versions are observed, not an archive-byte or provenance guarantee.
"""
import argparse
import hashlib
import json
from pathlib import Path
import platform
import re
import subprocess

from r800_android_userspace_preflight import read_regular
from r800_extract_super import require
from r800_graphics_donor_binding import checkout_sha
from r800_stage_adaptation_layer import valid_pin
from r800_verify_tizen_stage import unique_keys

PROFILE=Path(__file__).resolve().parent/"vm/r800-ubuntu-24.04-profile.json"
ENV={"PATH":"/usr/sbin:/usr/bin:/sbin:/bin","LC_ALL":"C","TZ":"UTC"}
MAX_REPORT=2*1024**2
MAX_ROWS=20000
PACKAGE=re.compile(r"[a-z0-9][a-z0-9+.-]*")
ARCH=re.compile(r"[a-z0-9][a-z0-9-]*")
VERSION=re.compile(r"[0-9][A-Za-z0-9.+:~\-]*")
FORMAT="${db:Status-Status}\t${Package}\t${Architecture}\t${Version}\n"


def parse(raw):
    require(isinstance(raw,bytes) and 0<len(raw)<=MAX_REPORT,"Package inventory exceeds budget")
    rows={}
    lines=raw.decode("utf-8").splitlines()
    require(len(lines)<=MAX_ROWS,"Package row budget exceeded")
    for line in lines:
        fields=line.split("\t")
        require(len(fields)==4,"Unexpected dpkg row")
        status,name,arch,version=fields
        if status in ("config-files","not-installed"):
            continue
        require(status=="installed","Incomplete package state: "+name)
        require(PACKAGE.fullmatch(name) and ARCH.fullmatch(arch) and VERSION.fullmatch(version),
                "Malformed installed package identity")
        key=name+":"+arch
        require(key not in rows,"Duplicate installed package: "+key)
        rows[key]={"package":name,"architecture":arch,"version":version}
    require(rows,"Empty installed package inventory")
    return dict(sorted(rows.items()))


def required_packages(profile,mode):
    require(profile["schema"]=="galwear-r800-vm-profile-v1" and
            profile["guest"]["distribution"]=="ubuntu" and profile["guest"]["release"]=="24.04" and
            profile["guest"]["architecture"]=="amd64","Unexpected VM profile")
    require(mode in ("assembly","compilation","guest-tests"),"Unexpected package mode")
    groups=["assembly"]+([] if mode=="assembly" else ["compilation"])+(
        ["optional_guest_tests"] if mode=="guest-tests" else [])
    names={n for group in groups for n in profile["packages"][group]}
    require(all(PACKAGE.fullmatch(n) for n in names),"Invalid required package name")
    return sorted(names)


def assess(rows,required):
    installed={r["package"] for r in rows.values() if r["architecture"] in ("amd64","all")}
    missing=sorted(set(required)-installed)
    foreign=sorted(k for k,r in rows.items() if r["architecture"] not in ("amd64","all"))
    return {"missing_required_packages":missing,"foreign_arch_packages":foreign}


def capture(source_sha,mode):
    checkout_sha(source_sha)
    release=platform.freedesktop_os_release()
    require(platform.system()=="Linux" and platform.machine()=="x86_64" and
            release.get("ID")=="ubuntu" and release.get("VERSION_ID")=="24.04",
            "Expected Ubuntu 24.04 x86_64 VM")
    raw=read_regular(PROFILE,1024*1024)
    profile=json.loads(raw,object_pairs_hook=unique_keys)
    required=required_packages(profile,mode)
    def observe():
        out=subprocess.check_output(["/usr/bin/dpkg-query","-W","-f="+FORMAT],
                                    env=ENV,timeout=60)
        return parse(out)
    rows=observe()
    require(observe()==rows and read_regular(PROFILE,1024*1024)==raw,
            "Package inventory or VM profile changed")
    checkout_sha(source_sha)
    checks=assess(rows,required)
    return {"schema":"galwear-r800-vm-package-lock-v1","source_sha":source_sha,
            "profile_sha256":hashlib.sha256(raw).hexdigest(),"mode":mode,
            "os":{"ID":"ubuntu","VERSION_ID":"24.04","architecture":"amd64"},
            "status":"VM_PACKAGE_REVIEW_REQUIRED" if any(checks.values()) else
                     "OBSERVED_PACKAGE_VERSIONS_ONLY",
            "required_packages":required,"packages":rows,**checks,
            "package_archive_bytes_verified":False,"package_origin_verified":False,
            "vm_isolation_verified":False,"reproducible_build_verified":False,
            "hardware_tested":False,"safe_to_flash":False}


def check(path,pin,source_sha,mode):
    path=Path(path).absolute()
    require(path.resolve(strict=True)==path,"Canonical package lock required")
    raw=read_regular(path,MAX_REPORT)
    require(valid_pin(pin) and hashlib.sha256(raw).hexdigest()==pin,"Package lock SHA-256 mismatch")
    saved=json.loads(raw,object_pairs_hook=unique_keys)
    observed=capture(source_sha,mode)
    require(saved==observed and read_regular(path,MAX_REPORT)==raw,"VM package inventory differs from lock")
    return observed


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--source-sha",required=True)
    p.add_argument("--profile",choices=("assembly","compilation","guest-tests"),default="assembly")
    p.add_argument("--mode",choices=("capture","check"),required=True)
    p.add_argument("--lock",type=Path)
    p.add_argument("--lock-sha256")
    a=p.parse_args()
    if a.mode=="capture":
        require(a.lock is None and a.lock_sha256 is None,"Capture writes lock to stdout")
        result=capture(a.source_sha,a.profile)
    else:
        require(a.lock is not None and a.lock_sha256 is not None,"Pinned package lock required")
        result=check(a.lock,a.lock_sha256,a.source_sha,a.profile)
    print(json.dumps(result,sort_keys=True,separators=(",",":")))
    return 0 if result["status"]=="OBSERVED_PACKAGE_VERSIONS_ONLY" else 2


if __name__=="__main__":
    raise SystemExit(main())
