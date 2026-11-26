#!/usr/bin/env python3
"""Audit only the GNSS ELF dependency closure of a verified raw ext4 image."""
import argparse
from collections import deque
import hashlib
import json
from pathlib import Path
import re
import shutil
import stat
import struct
import subprocess
import tempfile

from r800_extract_ext4 import command, snapshot_image, image_info
from r800_tizen_dependencies import audit, MAX_FILE, MAX_NODES, MAX_TOTAL
from r800_tizen_gnss_preflight import TARGETS, BRIDGE_LIBRARY, closure_review
from r800_gps_link_gate import elf
from r800_broadcom_export import assess

MAX_STATS = 4096
SAFE_PATH = re.compile(r"[A-Za-z0-9_./@+-]+")


class ImageResolver:
    """Resolve bounded guest paths without creating guest symlinks on host."""
    def __init__(self, tool, snapshot, scratch):
        self.tool, self.snapshot, self.scratch = tool, snapshot, scratch
        self.stats, self.files = {}, {}
        self.total = 0

    def stat_guest(self, guest):
        if guest in self.stats:
            return self.stats[guest]
        if len(self.stats)>=MAX_STATS:
            raise ValueError("ext4 lookup budget exceeded")
        if not SAFE_PATH.fullmatch(guest) or not guest.startswith("/") or \
                ".." in guest.split("/"):
            raise ValueError("Unsafe ext4 lookup path")
        result=command(self.tool,self.snapshot,"stat "+guest)
        if "File not found" in result.stderr:
            self.stats[guest]=None
            return None
        match=re.search(r"Inode:\s+(\d+)\s+Type:\s+(\w+)",result.stdout)
        size=re.search(r"\bSize:\s+(\d+)",result.stdout)
        if not match or not size:
            raise ValueError("Unrecognized ext4 stat: "+guest)
        kind=match[2]
        target=None
        if kind=="symlink":
            # Long/block-backed or unusual link formats are review-required.
            link=re.search(r'^Fast link dest: "([^"\r\n]+)"$',result.stdout,re.M)
            if not link or not SAFE_PATH.fullmatch(link[1]):
                raise ValueError("Unsupported ext4 symlink: "+guest)
            target=link[1]
        entry=(int(match[1]),kind,int(size[1]),target)
        self.stats[guest]=entry
        return entry

    def resolve(self, root, guest):
        if not guest.startswith("/") or not SAFE_PATH.fullmatch(guest):
            raise ValueError("Expected safe absolute guest path")
        pending=deque(guest.split("/")[1:])
        done=[]
        links=0
        entry=None
        while pending:
            part=pending.popleft()
            if part in ("","."):
                continue
            if part=="..":
                if not done:
                    raise ValueError("Guest symlink escapes image")
                done.pop()
                entry=None
                continue
            name="/"+"/".join(done+[part])
            entry=self.stat_guest(name)
            if entry is None:
                raise FileNotFoundError(name)
            if entry[1]=="symlink":
                links+=1
                if links>40:
                    raise ValueError("Guest symlink loop")
                target=entry[3]
                if target.startswith("/"):
                    done.clear()
                pending.extendleft(reversed(target.split("/")))
                entry=None
            else:
                if pending and entry[1]!="directory":
                    raise ValueError("Guest parent is not directory")
                done.append(part)
        canonical="/"+"/".join(done)
        if not canonical.startswith(("/usr/bin/","/bin/","/usr/lib/","/lib/")):
            raise ValueError("Guest ELF outside allowed directories")
        entry=self.stat_guest(canonical)
        if entry is None:
            raise FileNotFoundError(canonical)
        inode,kind,size,_=entry
        if kind!="regular" or not 0<size<=MAX_FILE:
            raise ValueError("Expected bounded regular ELF: "+canonical)
        target=root/canonical.lstrip("/")
        if canonical not in self.files:
            if len(self.files)>=MAX_NODES or self.total+size>MAX_TOTAL:
                raise ValueError("ext4 ELF extraction budget exceeded")
            member=self.scratch/"member"
            command(self.tool,self.snapshot,"dump <%d> member"%inode,cwd=self.scratch)
            st=member.lstat()
            if not stat.S_ISREG(st.st_mode) or st.st_size!=size:
                raise ValueError("Extracted ELF size mismatch")
            raw=member.read_bytes()
            target.parent.mkdir(parents=True,exist_ok=True)
            member.rename(target)
            target.chmod(0o400)
            self.files[canonical]={"inode":inode,"bytes":size,
                                   "sha256":hashlib.sha256(raw).hexdigest()}
            self.total+=size
        return target,canonical


def check_image(image, expected_sha):
    if not re.fullmatch(r"[0-9a-f]{64}",expected_sha):
        raise ValueError("Expected image SHA-256")
    tool=shutil.which("debugfs")
    if not tool:
        raise ValueError("Install debugfs")
    image=image.absolute()
    with tempfile.TemporaryDirectory(prefix="r800-gnss-image-") as tmp:
        scratch=Path(tmp)
        snapshot=scratch/"donor.img"
        identity=snapshot_image(image,snapshot,expected_sha)
        before=image_info(snapshot)
        if before["sha256"]!=expected_sha:
            raise ValueError("Snapshot SHA-256 mismatch")
        root=scratch/"elf"
        root.mkdir()
        resolver=ImageResolver(tool,snapshot,scratch)
        closure=audit(root,TARGETS,resolver=resolver.resolve)
        problems=closure_review(closure)
        library={"status":"NOT_VERIFIED"}
        try:
            path,canonical=resolver.resolve(root,BRIDGE_LIBRARY)
            raw=path.read_bytes()
            digest=hashlib.sha256(raw).hexdigest()
            if closure["files"].get(canonical,{}).get("sha256")!=digest:
                raise ValueError("Bridge library not bound to closure")
            library=assess(raw,elf(raw))
            if library["problems"]:
                problems.append("BRIDGE_EXPORT_NOT_CONFIRMED")
        except (OSError,ValueError,struct.error) as exc:
            library={"status":"REJECTED","reason":str(exc)}
            problems.append("BRIDGE_LIBRARY_REJECTED")
        for name,item in closure["files"].items():
            if resolver.files.get(name,{}).get("sha256")!=item["sha256"]:
                raise ValueError("Extracted closure hash mismatch")
        for name,item in resolver.files.items():
            if hashlib.sha256((root/name.lstrip("/")).read_bytes()).hexdigest()!=item["sha256"]:
                raise ValueError("Extracted file changed")
        st=image.lstat()
        if (st.st_dev,st.st_ino,st.st_mode,st.st_size,st.st_mtime_ns,st.st_ctime_ns)!=identity:
            raise ValueError("Donor image changed")
        if image_info(snapshot)!=before:
            raise ValueError("Donor snapshot changed")
        return {"schema":"r800-gnss-image-audit-v1",
                "status":"REVIEW_REQUIRED" if problems else "STATIC_IMAGE_GNSS_CLOSURE_ONLY",
                "image_sha256":expected_sha,"snapshot_verified":True,
                "problems":problems,"extracted_elf":resolver.files,
                "dependency_evidence":closure,"bridge_library":library,
                "runtime_paths_verified":False,"donor_authenticity_verified":False,
                "hardware_interface_abi_verified":False,"gnss_runtime_verified":False,
                "safe_to_flash":False}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--image",type=Path,required=True)
    p.add_argument("--sha256",required=True)
    a=p.parse_args()
    try:
        report=check_image(a.image,a.sha256)
    except (OSError,ValueError,struct.error,subprocess.SubprocessError) as exc:
        report={"status":"REVIEW_REQUIRED","problems":[str(exc)],"safe_to_flash":False}
    print(json.dumps(report,indent=2,sort_keys=True))
    return 2 if report["problems"] else 0


if __name__=="__main__":
    raise SystemExit(main())
