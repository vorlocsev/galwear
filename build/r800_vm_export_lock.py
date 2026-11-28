#!/usr/bin/env python3
"""Read-only integrity inventory of a powered-off, donor-free VM export.

Operator statements are not hypervisor observations. No VM is imported or
booted, and no archive is extracted or virtual disk mounted.
"""
import argparse
import hashlib
import json
from pathlib import Path
import stat

from r800_android_userspace_preflight import read_regular
from r800_donor_preflight import digest
from r800_extract_super import require
from r800_graphics_donor_binding import checkout_sha
from r800_stage_adaptation_layer import valid_pin
from r800_verify_tizen_stage import unique_keys
from r800_vm_package_lock import PROFILE, MAX_REPORT, MAX_ROWS, PACKAGE, ARCH, VERSION, required_packages, assess

REPO=Path(__file__).resolve().parents[1]
MAX_FILES=256
MAX_BYTES=512*1024**3
MAX_LOCK=2*1024**2
SUFFIXES={".ovf",".vmdk",".mf",".cert",".nvram"}


def pinned(path,pin,limit=MAX_LOCK):
    path=Path(path).absolute()
    require(path.resolve(strict=True)==path,"Canonical baseline evidence path required")
    raw=read_regular(path,limit)
    require(valid_pin(pin) and hashlib.sha256(raw).hexdigest()==pin,"Baseline evidence SHA-256 mismatch")
    return raw,json.loads(raw,object_pairs_hook=unique_keys)


def inventory(root):
    root=Path(root).absolute()
    require(root.resolve(strict=True)==root and root.is_dir() and
            not root.is_relative_to(REPO) and not REPO.is_relative_to(root),
            "Separate canonical export directory required")
    entries=sorted(root.iterdir())
    require(0<len(entries)<=MAX_FILES,"Export file count exceeds budget")
    files={}
    total=0
    for p in entries:
        require(p.name not in (".","..") and len(p.name)<=255 and
                all(c.isascii() and (c.isalnum() or c in "._- ") for c in p.name),
                "Unsupported export file name")
        st=p.lstat()
        require(stat.S_ISREG(st.st_mode) and st.st_nlink==1 and p.resolve(strict=True)==p,
                "Export must contain only regular nonlinked files")
        require(0<st.st_size<=MAX_BYTES-total,"Export byte budget exceeded")
        row=digest(p,MAX_BYTES-total)
        total+=row["bytes"]
        files[p.name]=row
    require(sorted(p.name for p in root.iterdir())==sorted(files),"Export inventory changed")
    suffixes=[Path(n).suffix.lower() for n in files]
    if suffixes==[".ova"]:
        fmt="OPAQUE_OVA"
    else:
        require(set(suffixes)<=SUFFIXES and suffixes.count(".ovf")==1 and ".vmdk" in suffixes,
                "Expected one OVA or flat OVF/VMDK export set")
        fmt="OPAQUE_OVF_VMDK_SET"
    return {"format":fmt,"files":files,"total_bytes":total}


def metadata(data,source,profile_pin,package_pin):
    fields={"schema","source_sha","profile_sha256","package_lock_sha256",
            "iso_sha256","hypervisor","hypervisor_version","snapshot_id",
            "powered_off","donor_free","physical_passthrough_disabled",
            "shared_host_folders_disabled","network_disconnected"}
    require(isinstance(data,dict) and set(data)==fields and
            data["schema"]=="galwear-r800-vm-export-declaration-v1" and
            data["source_sha"]==source and data["profile_sha256"]==profile_pin and
            data["package_lock_sha256"]==package_pin and valid_pin(data["iso_sha256"]),
            "Unexpected VM export declaration or binding")
    require(all(isinstance(data[k],str) and 0<len(data[k])<=256 and
                all(c.isprintable() for c in data[k])
                for k in ("hypervisor","hypervisor_version","snapshot_id")),
            "Missing operator VM identity")
    require(all(data[k] is True for k in ("powered_off","donor_free",
                "physical_passthrough_disabled","shared_host_folders_disabled","network_disconnected")),
            "Operator baseline safety declaration required")


def package_review(report,profile,profile_pin,source):
    require(report.get("schema")=="galwear-r800-vm-package-lock-v1" and
            report.get("source_sha")==source and report.get("profile_sha256")==profile_pin and
            report.get("status")=="OBSERVED_PACKAGE_VERSIONS_ONLY" and
            report.get("os")=={"ID":"ubuntu","VERSION_ID":"24.04","architecture":"amd64"} and
            all(report.get(k) is False for k in ("package_archive_bytes_verified",
                 "package_origin_verified","vm_isolation_verified","reproducible_build_verified",
                 "hardware_tested","safe_to_flash")),"Unexpected saved package lock scope")
    required=required_packages(profile,report["mode"])
    require(report["required_packages"]==required,"Package profile inventory mismatch")
    rows=report["packages"]
    require(isinstance(rows,dict) and 0<len(rows)<=MAX_ROWS,"Invalid saved package inventory")
    for key,row in rows.items():
        require(isinstance(row,dict) and set(row)=={"package","architecture","version"} and
                all(isinstance(v,str) for v in row.values()) and
                PACKAGE.fullmatch(row["package"]) and ARCH.fullmatch(row["architecture"]) and
                VERSION.fullmatch(row["version"]) and key==row["package"]+":"+row["architecture"],
                "Invalid saved package identity")
    checks=assess(rows,required)
    require(not any(checks.values()) and all(report.get(k)==v for k,v in checks.items()),
            "Saved package inventory requires review")


def capture(root,declaration,decl_pin,package,package_pin,source):
    checkout_sha(source)
    root=Path(root).absolute()
    for path in (declaration,package):
        require(not Path(path).absolute().is_relative_to(root),
                "Baseline evidence must be outside export directory")
    profile_raw=read_regular(PROFILE,1024*1024)
    profile=json.loads(profile_raw,object_pairs_hook=unique_keys)
    profile_pin=hashlib.sha256(profile_raw).hexdigest()
    require(Path(declaration).absolute()!=Path(package).absolute(),"Distinct baseline evidence files required")
    decl_raw,decl=pinned(declaration,decl_pin)
    pkg_raw,pkg=pinned(package,package_pin,MAX_REPORT)
    metadata(decl,source,profile_pin,package_pin)
    package_review(pkg,profile,profile_pin,source)
    observed=inventory(root)
    require(inventory(root)==observed,"Export changed during repeated inventory")
    require(pinned(declaration,decl_pin)[0]==decl_raw and
            pinned(package,package_pin,MAX_REPORT)[0]==pkg_raw and
            read_regular(PROFILE,1024*1024)==profile_raw,"Baseline evidence changed")
    checkout_sha(source)
    return {"schema":"galwear-r800-vm-export-lock-v1","source_sha":source,
            "status":"VM_EXPORT_BYTES_MATCH_DECLARED_BASELINE_ONLY",
            "profile_sha256":profile_pin,"package_lock_sha256":package_pin,
            "declaration_sha256":decl_pin,"operator_declaration":decl,
            "export":observed,"vm_contents_inspected":False,"vm_boot_verified":False,
            "vm_isolation_verified":False,"donor_free_verified":False,
            "reproducible_build_verified":False,"hardware_tested":False,"safe_to_flash":False}


def check(root,declaration,decl_pin,package,package_pin,lock,lock_pin,source):
    require(not Path(lock).absolute().is_relative_to(Path(root).absolute()),
            "Export lock must be outside export directory")
    raw,saved=pinned(lock,lock_pin)
    actual=capture(root,declaration,decl_pin,package,package_pin,source)
    require(saved==actual and pinned(lock,lock_pin)[0]==raw,"VM export differs from pinned baseline")
    return actual


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--mode",choices=("capture","check"),required=True)
    p.add_argument("--export",type=Path,required=True)
    p.add_argument("--declaration",type=Path,required=True)
    p.add_argument("--declaration-sha256",required=True)
    p.add_argument("--package-lock",type=Path,required=True)
    p.add_argument("--package-lock-sha256",required=True)
    p.add_argument("--source-sha",required=True)
    p.add_argument("--lock",type=Path)
    p.add_argument("--lock-sha256")
    a=p.parse_args()
    args=(a.export,a.declaration,a.declaration_sha256,a.package_lock,a.package_lock_sha256)
    if a.mode=="capture":
        require(a.lock is None and a.lock_sha256 is None,"Capture writes lock to stdout")
        result=capture(*args,a.source_sha)
    else:
        require(a.lock is not None and a.lock_sha256 is not None,"Pinned export lock required")
        result=check(*args,a.lock,a.lock_sha256,a.source_sha)
    print(json.dumps(result,indent=2,sort_keys=True))


if __name__=="__main__":
    main()
