#!/usr/bin/env python3
"""Read-only local Linux assembly environment lock and prerequisite check.

This is a selected executable-byte contract, not a hermetic build image.
No install, mount, privilege escalation, guest execution or compiler invocation.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import stat
import sys

from r800_android_userspace_preflight import read_regular
from r800_donor_preflight import digest
from r800_extract_super import require
from r800_graphics_donor_binding import checkout_sha
from r800_stage_adaptation_layer import valid_pin
from r800_verify_tizen_stage import unique_keys

SCHEMA="galwear-r800-linux-assembly-lock-v1"
REPORT_LIMIT=1024*1024
TOOL_LIMIT=256*1024**2
OS={"ID":"ubuntu","VERSION_ID":"24.04"}
SYSTEM_DIRS=(Path("/usr/bin"),Path("/usr/sbin"))
# Host commands used by the local development assembly and legacy vendor
# recipe. NDK tools and precompiled kernel/device inputs have separate pins.
TOOLS=tuple(sorted(set("""
    bash sh python3 git tar mount umount mountpoint unshare losetup
    llvm-readelf setfattr getfattr mkfs.ext4 mke2fs e2fsck debugfs
    sha256sum realpath mkdir rm cp chmod sed grep du find wc truncate
    basename dirname mktemp stat ln cat sort head tail readlink ls cmp mv
""".split()))))


def executable(name):
    found=shutil.which(name)
    require(found is not None,"Missing host tool: "+name)
    path=Path(found)
    require(path.is_absolute(),"Relative host tool on PATH: "+name)
    target=path.resolve(strict=True)
    require(any(target.is_relative_to(root) for root in SYSTEM_DIRS),
            "Host tool outside system directories: "+name)
    mode=target.lstat().st_mode
    require(stat.S_ISREG(mode) and mode&0o111,"Host tool is not executable: "+name)
    row=digest(target,TOOL_LIMIT)
    require(path.resolve(strict=True)==target,"Host tool target changed: "+name)
    return {**row,"resolved":str(target)}


def identity(source_sha):
    checkout_sha(source_sha)
    release=platform.freedesktop_os_release()
    require(platform.system()=="Linux" and platform.machine()=="x86_64" and
            {k:release.get(k) for k in OS}==OS,"Expected Ubuntu 24.04 Linux x86_64 candidate")
    require(sys.version_info[:2]>=(3,10),"Python 3.10+ required")
    tools={name:executable(name) for name in TOOLS}
    require(str(Path(sys.executable).resolve(strict=True))==tools["python3"]["resolved"],
            "Python interpreter differs from pinned PATH python3")
    checkout_sha(source_sha)
    return {"schema":SCHEMA,"source_sha":source_sha,"os":dict(OS),
            "architecture":"x86_64","python_version":platform.python_version(),
            "tools":tools,"complete_environment_verified":False,
            "dynamic_libraries_verified":False,"safe_to_flash":False}


def prerequisites():
    blockers=[]
    euid=os.geteuid()
    if euid!=0:
        blockers.append("Root required by existing vendor builder")
    cap=None
    try:
        # /proc is a virtual file, not a regular pinned build input.
        with open("/proc/self/status",encoding="ascii") as stream:
            for line in stream:
                if line.startswith("CapEff:"):
                    cap=int(line.split()[1],16)
                    break
    except (OSError,ValueError,IndexError):
        pass
    admin=cap is not None and bool(cap & (1<<21))
    if not admin:
        blockers.append("CAP_SYS_ADMIN not observed")
    try:
        loop=stat.S_ISCHR(Path("/dev/loop-control").stat().st_mode)
    except OSError:
        loop=False
    if not loop:
        blockers.append("Loop control device not observed")
    return {"effective_uid":euid,"cap_sys_admin_observed":admin,
            "loop_control_observed":loop,"kernel_release":platform.release(),
            "blockers":blockers,"private_mount_namespace_tested":False,
            "loop_mount_tested":False,"selinux_xattrs_tested":False}


def verify(lock_path,pin,source_sha):
    path=Path(lock_path).absolute()
    require(path.resolve(strict=True)==path,"Canonical environment lock required")
    raw=read_regular(path,REPORT_LIMIT)
    require(valid_pin(pin) and hashlib.sha256(raw).hexdigest()==pin,"Environment lock SHA-256 mismatch")
    expected=json.loads(raw,object_pairs_hook=unique_keys)
    observed=identity(source_sha)
    require(expected==observed,"Selected Linux assembly environment differs from lock")
    require(identity(source_sha)==observed and read_regular(path,REPORT_LIMIT)==raw,
            "Environment or lock changed during verification")
    checks=prerequisites()
    return {"schema":"galwear-r800-linux-assembly-review-v1","source_sha":source_sha,
            "status":"HOST_PREREQUISITES_REVIEW_REQUIRED" if checks["blockers"] else
                     "SELECTED_HOST_TOOLS_MATCH_PREREQUISITES_UNTESTED",
            "environment_lock_sha256":pin,"selected_tool_count":len(TOOLS),
            "prerequisites":checks,"hermetic_build_verified":False,
            "reproducible_build_verified":False,"hardware_tested":False,"safe_to_flash":False}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--mode",choices=("capture","check"),required=True)
    p.add_argument("--source-sha",required=True)
    p.add_argument("--lock",type=Path)
    p.add_argument("--lock-sha256")
    a=p.parse_args()
    if a.mode=="capture":
        require(a.lock is None and a.lock_sha256 is None,"Capture writes observed lock to stdout")
        result=identity(a.source_sha)
        require(identity(a.source_sha)==result,"Environment changed during capture")
    else:
        require(a.lock is not None and a.lock_sha256 is not None,"Pinned lock required for check")
        result=verify(a.lock,a.lock_sha256,a.source_sha)
    print(json.dumps(result,indent=2,sort_keys=True))
    return 2 if result.get("status")=="HOST_PREREQUISITES_REVIEW_REQUIRED" else 0


if __name__=="__main__":
    raise SystemExit(main())
