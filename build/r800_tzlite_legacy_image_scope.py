#!/usr/bin/env python3
"""Read-only bounded legacy scope inventory from a digest-bound raw ext4 snapshot."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile

from r800_extract_ext4 import command, snapshot_image, image_info
from r800_gps_image_audit import ImageResolver
from r800_tzlite_image_metadata import parse_inode
from r800_tzlite_image_xattrs import check_diagnostics
from r800_tzlite_legacy_scope import FILES, LINKS, REQUIRED_TREES, CONFIGS, SAFE_NAME
from r800_tizen_dependencies import MAX_FILE, MAX_TOTAL

MAX_ENTRIES=4096
MAX_DEPTH=16
MAX_LIST=2*1024*1024
MAX_DIRECTORY_BYTES=4*1024*1024


def parse_directory(text,limit):
    if len(text)>MAX_LIST:
        raise ValueError("Directory listing exceeds output budget")
    entries={}
    dots=set()
    for line in text.splitlines():
        if not line.strip():
            continue
        # debugfs ls -p: /inode/mode/uid/gid/name/size/
        fields=line.split("/")
        if len(fields)!=8 or fields[0] or fields[-1]:
            raise ValueError("Unrecognized ext4 directory listing")
        ino,mode,uid,gid,name,size=fields[1:-1]
        if (not re.fullmatch(r"[0-9]{1,10}",ino) or not 1<=int(ino)<2**32
                or not re.fullmatch(r"[0-7]{5,7}",mode)
                or any(not re.fullmatch(r"[0-9]{1,10}",v) or int(v)>=2**32 for v in (uid,gid))
                or (size and not re.fullmatch(r"[0-9]{1,20}",size))):
            raise ValueError("Invalid ext4 directory record")
        if name in (".",".."):
            if name in dots or not stat.S_ISDIR(int(mode,8)):
                raise ValueError("Invalid ext4 dot directory entry")
            dots.add(name)
            continue
        if not SAFE_NAME.fullmatch(name) or name in entries:
            raise ValueError("Unsupported or duplicate ext4 directory name")
        if len(entries)>=limit:
            raise ValueError("Directory entry budget exceeded")
        entries[name]=int(ino)
    if dots!={".",".."}:
        raise ValueError("Missing ext4 dot directory entries")
    return entries


def inspect_snapshot(resolver):
    entries={}
    issues=set()
    visited_dirs=set()
    total=0

    def locate(name):
        parts=name.strip("/").split("/")
        for idx in range(len(parts)):
            current="/"+"/".join(parts[:idx+1])
            found=resolver.stat_guest(current)
            if found is None:
                issues.add("MISSING:"+name)
                return None
            if idx<len(parts)-1 and found[1]!="directory":
                issues.add("PARENT_REVIEW:"+name)
                return None
        return found

    def visit(name,depth=0,recursive=False,expected_inode=None):
        nonlocal total
        if depth>MAX_DEPTH or len(entries)>=MAX_ENTRIES:
            raise ValueError("Legacy image entry or depth budget exceeded")
        found=locate(name)
        if found is None:
            if expected_inode is not None:
                raise ValueError("Listed directory entry not found")
            return
        inode,kind,size,target=found
        if expected_inode is not None and inode!=expected_inode:
            raise ValueError("Listed inode differs from stat")
        info=command(resolver.tool,resolver.snapshot,"stat <%d>"%inode)
        check_diagnostics(info.stderr)
        record=parse_inode(info.stdout,inode,kind)
        record["bytes_on_inode"]=size
        if kind=="symlink":
            record["target"]=target
            issues.add("SYMLINK_REVIEW:"+name)
        elif kind=="regular":
            if record["links"]!=1:
                record["status"]="NOT_HASHED_HARDLINK"
                issues.add("HARDLINK_REVIEW:"+name)
            else:
                if not 0<=size<=min(MAX_FILE,MAX_TOTAL-total):
                    raise ValueError("Legacy image byte budget exceeded")
                member=resolver.scratch/"legacy-member"
                if member.exists() or member.is_symlink():
                    raise ValueError("Unexpected private extraction file")
                try:
                    result=command(resolver.tool,resolver.snapshot,
                                   "dump <%d> legacy-member"%inode,cwd=resolver.scratch)
                    check_diagnostics(result.stderr)
                    st=member.lstat()
                    if not stat.S_ISREG(st.st_mode) or st.st_nlink!=1 or st.st_size!=size:
                        raise ValueError("Legacy image extraction size mismatch")
                    digest=hashlib.sha256()
                    with member.open("rb") as f:
                        first=f.read(4)
                        digest.update(first)
                        for block in iter(lambda:f.read(1024*1024),b""):
                            digest.update(block)
                    record.update(bytes=size,sha256=digest.hexdigest(),elf_candidate=first==b"\x7fELF")
                    total+=size
                finally:
                    member.unlink(missing_ok=True)
        elif kind!="directory":
            record["kind"]="special"
            issues.add("SPECIAL_OBJECT_REVIEW:"+name)
        entries[name]=record
        if recursive and kind=="directory":
            if inode in visited_dirs or not 0<size<=MAX_DIRECTORY_BYTES:
                raise ValueError("Repeated or oversized directory inode")
            visited_dirs.add(inode)
            listing=command(resolver.tool,resolver.snapshot,"ls -p <%d>"%inode)
            check_diagnostics(listing.stderr)
            children=parse_directory(listing.stdout,MAX_ENTRIES-len(entries))
            for child,child_inode in sorted(children.items()):
                visit(name+"/"+child,depth+1,True,child_inode)
        elif recursive:
            issues.add("TREE_ROOT_REVIEW:"+name)

    for name in FILES+LINKS:
        visit(name)
        item=entries.get(name)
        if name in FILES and item and item["kind"]!="regular":
            issues.add("CONFIG_OBJECT_REVIEW:"+name)
        if name in LINKS and item and item["kind"]!="symlink":
            issues.add("TOP_LEVEL_LINK_REVIEW:"+name)
    for name in REQUIRED_TREES:
        visit(name,recursive=True)
    return {"schema":"r800-tzlite-legacy-image-scope-v1",
            "status":"LEGACY_SCOPE_REVIEW_REQUIRED" if issues else "LEGACY_SCOPE_INVENTORY_ONLY",
            "problems":sorted(issues),"entries":entries,"regular_bytes_hashed":total,
            "elf_candidates":sorted(n for n,v in entries.items() if v.get("elf_candidate")),
            "outside_four_config_baseline":sorted(n for n,v in entries.items()
                                                   if v["kind"]=="regular" and n not in CONFIGS),
            "symlinks_followed":False,"files_staged":False,"guest_executed":False,
            "complete_plugin_inventory_verified":False,"donor_authenticity_verified":False,
            "runtime_verified":False,"safe_to_flash":False}


def inspect_image(image,sha,*,audit_plugins=False,extended_manifest=False,review_configs=False):
    if not re.fullmatch(r"[0-9a-f]{64}",sha):
        raise ValueError("Expected lowercase image SHA-256")
    tool=shutil.which("debugfs")
    if not tool:
        raise ValueError("Install debugfs")
    image=image.absolute()
    with tempfile.TemporaryDirectory(prefix="r800-legacy-image-") as tmp:
        scratch=Path(tmp)
        snapshot=scratch/"donor.img"
        identity=snapshot_image(image,snapshot,sha)
        before=image_info(snapshot)
        if before["sha256"]!=sha:
            raise ValueError("Snapshot digest mismatch")
        resolver=ImageResolver(tool,snapshot,scratch)
        report=inspect_snapshot(resolver)
        if audit_plugins or extended_manifest:
            from r800_tzlite_extra_plugins import check
            report["extra_plugin_audit"]=check(resolver,report)
            if report["extra_plugin_audit"]["problems"]:
                report["problems"]=sorted(set(report["problems"]+["EXTRA_PLUGIN_CLOSURE_REVIEW"]))
                report["status"]="LEGACY_SCOPE_REVIEW_REQUIRED"
        if extended_manifest:
            from r800_tzlite_extended_manifest import build
            plugin_report=report["extra_plugin_audit"]
            scope={k:v for k,v in report.items() if k!="extra_plugin_audit"}
            report["extended_manifest"]=build(sha,scope,plugin_report)
            from r800_tzlite_metadata_plan import digest
            report["extended_manifest_sha256"]=digest(report["extended_manifest"])
        if review_configs:
            from r800_tzlite_config_review import inspect_snapshot as inspect_configs
            from r800_tzlite_metadata_plan import digest
            config_report=inspect_configs(resolver,report)
            report["extra_config_review"]=config_report
            report["extra_config_review_sha256"]=digest(config_report)
        st=image.lstat()
        if (st.st_dev,st.st_ino,st.st_mode,st.st_size,st.st_mtime_ns,st.st_ctime_ns)!=identity:
            raise ValueError("Donor image changed")
        if image_info(snapshot)!=before:
            raise ValueError("Donor snapshot changed")
        return dict(report,image_sha256=sha,snapshot_verified=True)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--image",required=True,type=Path)
    p.add_argument("--sha256",required=True)
    p.add_argument("--audit-plugins",action="store_true")
    p.add_argument("--extended-manifest",action="store_true")
    p.add_argument("--review-configs",action="store_true")
    a=p.parse_args()
    try:
        report=inspect_image(a.image,a.sha256,audit_plugins=a.audit_plugins,
                             extended_manifest=a.extended_manifest,review_configs=a.review_configs)
    except (OSError,ValueError,subprocess.SubprocessError,RecursionError) as exc:
        report={"schema":"r800-tzlite-legacy-image-scope-v1","status":"LEGACY_SCOPE_REVIEW_REQUIRED",
                "problems":[str(exc)],"safe_to_flash":False}
    print(json.dumps(report,indent=2,sort_keys=True))
    return 2 if report["problems"] else 0


if __name__=="__main__":
    raise SystemExit(main())
