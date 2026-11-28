#!/usr/bin/env python3
"""Explicit synthetic-only Linux capability probe; run in a dedicated VM.

Creates one new EXT4 file. Never takes donor/device paths, never mounts a
physical block device, and never invokes a guest executable. Not a CI gate.
"""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time

from r800_extract_super import require
from r800_linux_assembly_environment import verify
from r800_graphics_donor_binding import checkout_sha

ENV={"PATH":"/usr/sbin:/usr/bin:/sbin:/bin","LC_ALL":"C","TZ":"UTC"}
CHECKS=("private_namespace","rw_loop_mount","selinux_xattr",
        "tar_xattr_roundtrip","ro_remount_persistence","unmount")
CHILD=r'''
import json, os, pathlib, subprocess, sys
root=pathlib.Path(sys.argv[1])
parent_namespace=sys.argv[2]
image=root/"fixture.img"
mnt=root/"mount"
env={"PATH":"/usr/sbin:/usr/bin:/sbin:/bin","LC_ALL":"C","TZ":"UTC"}
label="u:object_r:vendor_file:s0"
checks={}
def run(*args):
    return subprocess.run(args,env=env,check=True,capture_output=True,timeout=30)
def check(test,message):
    if not test:
        raise RuntimeError(message)
def mounted():
    return subprocess.run(["mountpoint","-q",str(mnt)],env=env,timeout=10).returncode==0
def read_label(path):
    return run("getfattr","-n","security.selinux","--only-values",str(path)).stdout.decode().rstrip("\n")
check(os.readlink("/proc/self/ns/mnt")!=parent_namespace,"Mount namespace is not private")
with open("/proc/self/mountinfo",encoding="utf-8") as f:
    for line in f:
        left=line.split(" - ",1)[0].split()
        check(not any(x.startswith(("shared:","master:","propagate_from:")) for x in left[6:]),
              "Mount propagation is not private")
checks["private_namespace"]=True
check(not mounted(),"Fixture mountpoint already mounted")
try:
    run("mount","-t","ext4","-o","loop,nodev,nosuid,noexec",str(image),str(mnt))
    check(mounted(),"Synthetic loop mount not observed")
    checks["rw_loop_mount"]=True
    original=mnt/"original"
    original.write_bytes(b"GalWear synthetic fixture\n")
    run("setfattr","-n","security.selinux","-v",label,str(original))
    check(read_label(original)==label,"SELinux label mismatch")
    checks["selinux_xattr"]=True
    target=mnt/"roundtrip"
    target.mkdir()
    archive=root/"fixture.tar"
    run("tar","--xattrs","--xattrs-include=*","-C",str(mnt),"-cf",str(archive),"original")
    run("tar","--xattrs","--xattrs-include=*","-C",str(target),"-xpf",str(archive))
    check((target/"original").read_bytes()==original.read_bytes() and
          read_label(target/"original")==label,"Tar xattr roundtrip mismatch")
    checks["tar_xattr_roundtrip"]=True
    run("umount",str(mnt))
    check(not mounted(),"RW fixture still mounted")
    run("mount","-t","ext4","-o","loop,ro,noload,nodev,nosuid,noexec",str(image),str(mnt))
    check(mounted() and (mnt/"roundtrip"/"original").read_bytes()==b"GalWear synthetic fixture\n" and
          read_label(mnt/"roundtrip"/"original")==label,"Read-only remount persistence mismatch")
    checks["ro_remount_persistence"]=True
finally:
    if mounted():
        run("umount",str(mnt))
    check(not mounted(),"Fixture still mounted")
checks["unmount"]=True
print(json.dumps(checks,sort_keys=True))
'''


def command(args,timeout):
    return subprocess.run(args,env=ENV,check=True,capture_output=True,text=True,timeout=timeout)


def detached(image):
    # Only inspect associations to this newly created file. Never detach
    # arbitrary devices, including on failure.
    for _ in range(10):
        if not command(["losetup","-j",str(image)],10).stdout.strip():
            return True
        time.sleep(0.2)
    return False


def probe(workspace,lock,pin,source_sha):
    checkout_sha(source_sha)
    require(os.environ.get("PATH")==ENV["PATH"],"Set the documented system PATH")
    root=Path(workspace).absolute()
    repo=Path(__file__).resolve().parents[1]
    require(root.resolve(strict=True)==root and root.is_dir() and
            not root.is_relative_to(repo) and not repo.is_relative_to(root) and
            re.fullmatch(r"/[A-Za-z0-9_./+-]+",str(root)),
            "Separate canonical synthetic workspace required")
    before=verify(lock,pin,source_sha)
    require(not before["prerequisites"]["blockers"],"Host prerequisites review required")
    scratch=Path(tempfile.mkdtemp(prefix="r800-mount-probe-",dir=root))
    image=scratch/"fixture.img"
    checks={}
    error=None
    cleanup=False
    try:
        with image.open("xb") as f:
            f.truncate(32*1024**2)
        (scratch/"mount").mkdir()
        command(["mkfs.ext4","-q","-F","-b","4096","-O","^metadata_csum,^64bit",str(image)],60)
        parent=os.readlink("/proc/self/ns/mnt")
        child=command(["unshare","--mount","--propagation","private",
                       "--fork","--kill-child","--",sys.executable,"-I","-c",CHILD,
                       str(scratch),parent],240)
        checks=json.loads(child.stdout)
        require(set(checks)==set(CHECKS) and all(v is True for v in checks.values()),
                "Incomplete synthetic mount checks")
        command(["e2fsck","-fn",str(image)],60)
        checks["offline_fsck"]=True
    except (OSError,ValueError,RuntimeError,subprocess.SubprocessError) as exc:
        error=str(exc)[:1000]
    finally:
        try:
            cleanup=not image.exists() or detached(image)
            # Parent must never see the private mount, even on failure.
            if (scratch/"mount").exists():
                result=subprocess.run(["mountpoint","-q",str(scratch/"mount")],env=ENV,timeout=10)
                cleanup=cleanup and result.returncode==32
        except (OSError,subprocess.SubprocessError):
            cleanup=False
        if cleanup:
            shutil.rmtree(scratch)
    after=verify(lock,pin,source_sha)
    require(before==after,"Host evidence changed during synthetic probe")
    checkout_sha(source_sha)
    passed=error is None and cleanup
    return {"schema":"galwear-r800-synthetic-mount-probe-v1","source_sha":source_sha,
            "environment_lock_sha256":pin,
            "status":"SYNTHETIC_EXT4_MOUNT_XATTR_PASS_ONLY" if passed else "REVIEW_REQUIRED",
            "checks":checks,"loop_detached_and_workspace_removed":cleanup,
            "retained_fixture":None if cleanup else str(scratch),
            "error":error,"donor_images_used":False,"physical_devices_used":False,
            "vendor_build_verified":False,"reproducible_build_verified":False,
            "hardware_tested":False,"safe_to_flash":False}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--workspace",type=Path,required=True)
    p.add_argument("--lock",type=Path,required=True)
    p.add_argument("--lock-sha256",required=True)
    p.add_argument("--source-sha",required=True)
    p.add_argument("--confirm-dedicated-vm",action="store_true",required=True)
    a=p.parse_args()
    result=probe(a.workspace,a.lock,a.lock_sha256,a.source_sha)
    print(json.dumps(result,indent=2,sort_keys=True))
    return 0 if result["status"]=="SYNTHETIC_EXT4_MOUNT_XATTR_PASS_ONLY" else 2


if __name__=="__main__":
    raise SystemExit(main())
