#!/usr/bin/env python3
"""Extract explicit Samsung donor files from a local, hash-identified TAR/AP archive."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile

MAX_ARCHIVE = 8 * 1024**3
MAX_IMAGE = 4 * 1024**3
PROFILES = {
    "j4": ("vendor.img",),
    "r800": ("rootfs.img", "param.bin"),
}
BUFFER = 1024*1024

def digest(path):
    st = path.lstat()
    if not stat.S_ISREG(st.st_mode) or not 0 < st.st_size <= MAX_ARCHIVE:
        raise ValueError("Expected bounded regular Samsung archive")
    h = hashlib.sha256()
    with path.open("rb") as f:
        for data in iter(lambda: f.read(BUFFER), b""):
            h.update(data)
    return h.hexdigest()

def copy_bounded(inp, dest, maximum):
    h = hashlib.sha256()
    size = 0
    with dest.open("xb") as out:
        while True:
            data = inp.read(BUFFER)
            if not data:
                break
            size += len(data)
            if size > maximum:
                raise ValueError("Donor output exceeds byte budget")
            out.write(data)
            h.update(data)
    if not size:
        raise ValueError("Empty donor output")
    return {"bytes": size, "sha256": h.hexdigest()}

def decode_lz4(source, dest):
    tool = shutil.which("lz4")
    if not tool:
        raise ValueError("Install lz4 to decode compressed Samsung donors")
    with source.open("rb") as f:
        if f.read(4) not in (b"\x04\x22\x4d\x18", b"\x02\x21\x4c\x18"):
            raise ValueError("Expected LZ4 frame or legacy magic")
    with subprocess.Popen([tool, "-d", "-c", str(source)], stdout=subprocess.PIPE) as proc:
        try:
            info = copy_bounded(proc.stdout, dest, MAX_IMAGE)
            if proc.wait(timeout=60) != 0:
                raise ValueError("LZ4 decompression failed")
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait()
    return info

def classify(path):
    with path.open("rb") as f:
        head = f.read(1082)
    if head[:4] == b"\x3a\xff\x26\xed":
        return "android_sparse"
    if head[1080:1082] == b"\x53\xef":
        return "raw_ext4"
    if head[:4] == b"hsqs":
        return "squashfs"
    return "unknown_or_container"

def extract(archive, output, profile, expected_sha):
    archive, output = Path(archive).absolute(), Path(output).absolute()
    if profile not in PROFILES or not re.fullmatch(r"[0-9a-f]{64}", expected_sha):
        raise ValueError("Expected explicit donor profile and SHA-256")
    if output.exists() or output.is_symlink():
        raise ValueError("Output already exists")
    if digest(archive) != expected_sha:
        raise ValueError("Samsung archive SHA-256 mismatch")
    allowed = PROFILES[profile]
    with tempfile.TemporaryDirectory(dir=output.parent) as tmp:
        root = Path(tmp)
        tree = root/"images"
        tree.mkdir()
        found = {}
        # Samsung TAR.MD5 may have a trailer. The supplied whole-file SHA-256
        # covers it; the trailer is not treated as proof of authenticity.
        with tarfile.open(archive,"r:") as tar:
            for i, member in enumerate(tar):
                if i >= 256:
                    raise ValueError("Too many AP archive members")
                logical = member.name.removesuffix(".lz4")
                if logical not in allowed:
                    continue
                if logical in found or not member.isfile() or not 0 < member.size <= MAX_IMAGE:
                    raise ValueError("Duplicate or invalid donor member: " + logical)
                dest = tree/logical
                compressed = member.name.endswith(".lz4")
                with tar.extractfile(member) as stream:
                    if compressed:
                        intermediate = root/"input.lz4"
                        encoded = copy_bounded(stream,intermediate,MAX_IMAGE)
                        if encoded["bytes"] != member.size:
                            raise ValueError("Truncated AP member")
                        info = decode_lz4(intermediate,dest)
                        intermediate.unlink()
                    else:
                        info = copy_bounded(stream,dest,MAX_IMAGE)
                        if info["bytes"] != member.size:
                            raise ValueError("Truncated AP member")
                fmt = classify(dest)
                if logical == "vendor.img" and fmt not in ("android_sparse","raw_ext4"):
                    raise ValueError("Unsupported J4 vendor format")
                if logical == "rootfs.img" and fmt not in ("raw_ext4","squashfs","android_sparse"):
                    raise ValueError("Unsupported R800 rootfs format")
                found[logical] = {**info,"format":fmt,"compressed":compressed}
        if set(found) != set(allowed):
            raise ValueError("Missing donor members: " + ", ".join(sorted(set(allowed)-set(found))))
        if digest(archive) != expected_sha:
            raise ValueError("Samsung archive changed during extraction")
        report = {"status":"SAMSUNG_DONOR_EXTRACTED_ONLY","profile":profile,
                  "archive_sha256":expected_sha,"images":found,
                  "donor_authenticity_verified":False,"device_compatibility_verified":False,
                  "safe_to_flash":False}
        (tree/"samsung-evidence.json").write_text(json.dumps(report,indent=2,sort_keys=True))
        os.rename(tree,output)
    return report

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--archive",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True)
    p.add_argument("--profile",choices=PROFILES,required=True)
    p.add_argument("--sha256",required=True)
    a=p.parse_args()
    print(json.dumps(extract(a.archive,a.output,a.profile,a.sha256),sort_keys=True))

if __name__=="__main__":
    main()
