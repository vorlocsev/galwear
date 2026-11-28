#!/usr/bin/env python3
"""Stage selected stock Tizen daemon configs and chroot mountpoint layout.

No personal device backups, shadow databases, /opt GNSS state, plugin guessing,
policy bypasses or execution. Account tables are read from a clean rootfs;
password hashes are refused. This is a minimal literal configuration subset.
"""
import hashlib
from pathlib import Path
import re
import shutil
import stat
import tempfile

from r800_extract_ext4 import snapshot_image
from r800_framework_inventory import ext4_member
from r800_stage_android_layer import metadata, directory
from r800_partition_identity import filesystem
from r800_donor_preflight import digest, MAX_DONOR
from r800_extract_super import require
from r800_verify_tizen_stage import guest_name

PREFIX="r800dev/tzlite"
CONFIGS=("/etc/lhd/lhd.conf","/etc/gps-manager/brcm/gpsd.xml","/etc/passwd","/etc/group")
CONFIG_PATHS={PREFIX+p for p in CONFIGS}
MOUNTPOINTS={PREFIX+"/"+n:"0o755" for n in ("dev","proc","sys","tmp","run","opt","mnt")}
MAX_CONFIG=1024*1024


def account_table(raw,kind):
    text=raw.decode("utf-8")
    entries={}
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        fields=line.split(":")
        require(len(fields)==(7 if kind=="passwd" else 4) and
                re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]*[$]?",fields[0]) and
                fields[0] not in entries and fields[1] in ("","x","*","!","!!","!*") and
                re.fullmatch(r"[0-9]{1,10}",fields[2]) and int(fields[2])<2**32-1,
                "Invalid or secret-bearing "+kind+" record")
        if kind=="passwd":
            require(re.fullmatch(r"[0-9]{1,10}",fields[3]) and int(fields[3])<2**32-1,
                    "Invalid passwd group ID")
        entries[fields[0]]=fields
    require("root" in entries and entries["root"][2]=="0" and "location" in entries,
            "Root and location account/group required in "+kind)
    return entries


def inspect_config(data):
    require(set(data)==set(CONFIGS),"Exact selected Tizen configuration required")
    for path,raw in data.items():
        require(0<len(raw)<=MAX_CONFIG and b"\0" not in raw,"Invalid config size or NUL: "+path)
        raw.decode("utf-8")
    users=account_table(data["/etc/passwd"],"passwd")
    groups=account_table(data["/etc/group"],"group")
    uid,gid=int(users["location"][2]),int(users["location"][3])
    require(uid>0 and gid>0 and gid==int(groups["location"][2]),
            "Location user/group identity mismatch")
    return {"location_uid":uid,"location_gid":gid,
            "daemon_config_semantics_verified":False}


def extract_configs(image,pin,scratch):
    tool=shutil.which("debugfs")
    require(tool,"debugfs required")
    with tempfile.TemporaryDirectory(dir=scratch,prefix="tizen-config-") as tmp:
        work=Path(tmp)
        copy=work/"rootfs.img"
        snapshot_image(Path(image),copy,pin)
        require(filesystem(copy)["kind"]=="EXT4","Raw Tizen EXT4 required")
        data={}
        for path in CONFIGS:
            for parent in reversed(Path(path).parents):
                if str(parent)!="/":
                    directory(tool,copy,str(parent))
            meta=metadata(tool,copy,path)
            require(meta["type"]=="regular" and not meta["mode"]&0o7000,
                    "Expected nonprivileged regular config: "+path)
            raw=ext4_member(tool,copy,path,MAX_CONFIG,work)
            require(raw is not None,"Missing Tizen config: "+path)
            data[path]=raw
        identity=inspect_config(data)
        require(digest(copy,MAX_DONOR)["sha256"]==pin and digest(Path(image),MAX_DONOR)["sha256"]==pin,
                "Tizen image changed during config extraction")
    return data,identity


def layout(report,files):
    """Old fixture layers may lack a layout, but cannot contain config paths."""
    dirs=report.get("chroot_mountpoints",{})
    require(dirs=={} or dirs==MOUNTPOINTS,"Unexpected Tizen mountpoint layout")
    present=CONFIG_PATHS&set(files)
    require(present==(CONFIG_PATHS if dirs else set()),"Incomplete Tizen config/layout binding")
    for name in present:
        require(files[name]["mode"]=="0o644" and 0<files[name]["bytes"]<=MAX_CONFIG,
                "Invalid Tizen config metadata")
    return dirs


def check_guest(path,dirs):
    if dirs and path in CONFIG_PATHS:
        return
    guest_name(path.removeprefix(PREFIX))


def materialize(root,dirs):
    for name,mode in sorted(dirs.items()):
        p=root/name
        p.mkdir(parents=True,exist_ok=False)
        p.chmod(int(mode,8))


def verify_dir(path,relative,dirs):
    if relative in dirs:
        require(oct(stat.S_IMODE(path.lstat().st_mode))==dirs[relative],
                "Tizen mountpoint mode mismatch: "+relative)
