#!/usr/bin/env python3
"""Extract one explicit stock Samsung partition from a pinned local archive.

No download, device I/O, mounting, flash package or extraction of arbitrary
archive paths. The selected donor remains a candidate, not an authenticated
stock image. Use only archives that you are entitled to process.
"""
import argparse
import json
import os
from pathlib import Path
import resource
import shutil
import subprocess
import tarfile
import tempfile

from r800_donor_preflight import digest, MAX_DONOR
from r800_extract_ext4 import snapshot_image
from r800_extract_super import normalize, require
from r800_graphics_donor_binding import checkout_sha
from r800_partition_identity import filesystem, inspect_partition
from r800_stage_adaptation_layer import valid_pin

ROLES={"r800-rootfs":("rootfs.img","rootfs.img.lz4"),
       "j4-vendor":("vendor.img","vendor.img.lz4","vendor.img.ext4","vendor.img.ext4.lz4")}
MAX_MEMBERS=256


def select(archive,role,dest):
    require(role in ROLES,"Unsupported Samsung donor role")
    found=None
    with tarfile.open(archive,"r:") as tar:
        for index,member in enumerate(tar):
            require(index<MAX_MEMBERS,"Too many stock archive members")
            if member.name not in ROLES[role]:
                continue
            require(found is None,"Ambiguous selected stock partition")
            require(member.isfile() and 0<member.size<=MAX_DONOR,
                    "Expected bounded regular selected partition")
            found=member
        require(found is not None,"Selected stock partition missing")
        stream=tar.extractfile(found)
        require(stream is not None,"Cannot read selected stock partition")
        count=0
        with stream,dest.open("xb") as out:
            while True:
                block=stream.read(1024*1024)
                if not block:
                    break
                count+=len(block)
                require(count<=found.size,"Selected partition grew during read")
                out.write(block)
        require(count==found.size,"Selected partition length mismatch")
    dest.chmod(0o400)
    return found.name


def decompress_lz4(source,dest):
    tool=shutil.which("lz4")
    require(tool is not None,"lz4 tool required for compressed stock member")
    def limits():
        resource.setrlimit(resource.RLIMIT_FSIZE,(MAX_DONOR,MAX_DONOR))
        resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    with dest.open("xb") as out:
        subprocess.run([tool,"-d","-c","--",str(source)],stdout=out,
                       stderr=subprocess.DEVNULL,check=True,timeout=600,preexec_fn=limits)
    dest.chmod(0o400)
    return digest(dest,MAX_DONOR)


def extract_stock(archive,pin,role,output,source_sha):
    checkout_sha(source_sha)
    require(role in ROLES and valid_pin(pin),"Explicit stock donor role and SHA-256 required")
    archive,output=(Path(p).absolute() for p in (archive,output))
    repo=Path(__file__).resolve().parents[1]
    require(archive.resolve(strict=True)==archive and archive.is_file(),
            "Canonical local stock archive required")
    require(not output.exists() and not output.is_symlink() and
            not output.resolve().is_relative_to(repo),"Fresh output outside checkout required")
    with tempfile.TemporaryDirectory(dir=output.parent,prefix="r800-stock-intake-") as tmp:
        work=Path(tmp)
        stage=work/"result"
        stage.mkdir()
        copy=work/"stock.tar"
        snapshot_image(archive,copy,pin)
        original=digest(copy,MAX_DONOR)
        member=work/"member"
        name=select(copy,role,member)
        compressed=digest(member,MAX_DONOR)
        if name.endswith(".lz4"):
            expanded=work/"expanded"
            uncompressed=decompress_lz4(member,expanded)
        else:
            expanded=member
            uncompressed=compressed
        target=stage/("rootfs.img" if role=="r800-rootfs" else "vendor.img")
        normalization=normalize(expanded,target,uncompressed["sha256"])
        observed=digest(target,MAX_DONOR)
        require(observed=={"bytes":normalization["raw_bytes"],
                           "sha256":normalization["raw_sha256"]},
                "Raw donor identity mismatch")
        fs=filesystem(target)
        require(fs["kind"]=="EXT4","Raw EXT4 required by current donor pipeline")
        identity=None
        if role=="j4-vendor":
            identity=inspect_partition(target,observed["sha256"],"vendor",source_sha)
            require(identity["filesystem"]==fs,"Vendor geometry changed")
        require(digest(copy,MAX_DONOR)==digest(archive,MAX_DONOR)==original and
                digest(member,MAX_DONOR)==compressed and
                digest(expanded,MAX_DONOR)==uncompressed and digest(target,MAX_DONOR)==observed,
                "Stock archive or extracted bytes changed")
        checkout_sha(source_sha)
        report={"schema":"galwear-r800-stock-donor-v1","status":"STOCK_PARTITION_CANDIDATE_ONLY",
                "source_sha":source_sha,"role":role,"archive":original,"member":name,
                "member_identity":compressed,"decompressed_identity":uncompressed,
                "normalization":normalization,"partition":{"file":target.name,**observed},
                "filesystem":fs,"android_identity":identity,"donor_model_verified":False,
                "donor_authenticity_verified":False,"runtime_verified":False,
                "hardware_tested":False,"safe_to_flash":False}
        (stage/"stock-donor-evidence.json").write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
        require(not output.exists() and not output.is_symlink(),"Output already exists")
        os.rename(stage,output)
    return report


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--archive",required=True,type=Path)
    p.add_argument("--archive-sha256",required=True)
    p.add_argument("--role",choices=ROLES,required=True)
    p.add_argument("--output",required=True,type=Path)
    p.add_argument("--source-sha",required=True)
    a=p.parse_args()
    print(extract_stock(a.archive,a.archive_sha256,a.role,a.output,a.source_sha)["status"])


if __name__=="__main__":
    main()
