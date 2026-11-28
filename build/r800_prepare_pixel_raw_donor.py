#!/usr/bin/env python3
"""Materialize selected raw donor partitions from a local pinned Pixel factory ZIP.

This is a donor intake pipeline, not R800 system adaptation or a flash package.
Use only lawfully available input files. No downloads, mounts or guest execution.
"""
import argparse
import json
import os
from pathlib import Path
import re
import tempfile

from r800_extract_pixel_factory import FACTORY_SHA256, extract as extract_factory, digest as factory_digest
from r800_extract_super import normalize, extract as extract_super, ALLOWED, require
from r800_partition_identity import filesystem, inspect_partition
from r800_donor_preflight import digest, MAX_DONOR
from r800_graphics_donor_binding import checkout_sha


def prepare(archive, output, source_sha, mode, names, slot=None, *, expected=FACTORY_SHA256):
    checkout_sha(source_sha)
    archive=Path(archive).absolute()
    output=Path(output).absolute()
    repo=Path(__file__).resolve().parents[1]
    require(archive.resolve(strict=True)==archive and archive.is_file(),
            "Canonical local factory archive required")
    require(not output.exists() and not output.is_symlink() and
            not output.resolve().is_relative_to(repo),"Fresh output outside checkout required")
    require(mode in ("direct","super") and 0<len(names)<=5 and len(set(names))==len(names)
            and all(ALLOWED.fullmatch(n) for n in names),"Explicit unique selected partitions required")
    bases=[re.sub(r"_[ab]$","",n) for n in names]
    require("system" in bases and len(set(bases))==len(bases),"Select exactly one system and no duplicate partition roles")
    if mode=="direct":
        require(slot is None and set(names)<={"system","vendor"},"Direct mode accepts system and optional vendor without slot")
    else:
        require(type(slot) is int and slot in (0,1),"Explicit A/B metadata slot required")
        suffix="_a" if slot==0 else "_b"
        require(all(n.endswith(suffix) for n in names) or all(n==b for n,b in zip(names,bases)),
                "Selected partition names must match the explicit slot or be unsuffixed")
    with tempfile.TemporaryDirectory(dir=output.parent,prefix="r800-pixel-intake-") as tmp:
        work=Path(tmp)
        extracted=work/"factory"
        factory=extract_factory(archive,extracted,expected)
        tree=work/"result"
        tree.mkdir()
        images=factory["images"]
        provenance={}
        if mode=="direct":
            require(all(n+".img" in images for n in names),"Selected direct factory image absent")
            for n in names:
                src=extracted/(n+".img")
                row=images[src.name]
                dest=tree/src.name
                origin=normalize(src,dest,row["sha256"])
                require(origin["source_bytes"]==row["bytes"],"Factory member size changed")
                provenance[n]=origin
            super_evidence=None
        else:
            require("super.img" in images,"Factory super image absent")
            super_evidence=extract_super(extracted/"super.img",images["super.img"]["sha256"],
                                         slot,names,work/"logical",source_sha)
            for n in names:
                row=super_evidence["partitions"][n]
                src=work/"logical"/row["file"]
                require(digest(src,MAX_DONOR)=={"bytes":row["bytes"],"sha256":row["sha256"]},
                        "Logical partition bytes changed")
                os.rename(src,tree/(n+".img"))
                provenance[n]={"source":"super.img","metadata_slot":slot,
                               "raw_bytes":row["bytes"],"raw_sha256":row["sha256"]}
        files={}
        for n in names:
            image=tree/(n+".img")
            observed=digest(image,MAX_DONOR)
            require(observed=={"bytes":provenance[n]["raw_bytes"],"sha256":provenance[n]["raw_sha256"]},
                    "Normalized donor bytes mismatch")
            fs=filesystem(image)
            identity=inspect_partition(image,observed["sha256"],n,source_sha)
            require(identity["filesystem"]==fs,"Partition geometry changed")
            files[n]={"file":image.name,**observed,"filesystem":fs,
                      "identity":identity,"provenance":provenance[n]}
        require(factory_digest(archive)==expected,"Factory archive changed")
        checkout_sha(source_sha)
        result={"schema":"galwear-r800-pixel-raw-donor-v1",
                "status":"SELECTED_PIXEL_RAW_DONOR_PARTITIONS_ONLY",
                "source_sha":source_sha,"factory_sha256":expected,
                "documented_factory_pin_matched":expected==FACTORY_SHA256,
                "factory_extraction":factory,"mode":mode,"metadata_slot":slot,
                "super_extraction":super_evidence,"partitions":files,
                "system_adaptation_verified":False,"donor_authenticity_verified":False,
                "wear_os_runtime_verified":False,"r800_compatibility_verified":False,
                "hardware_tested":False,"safe_to_flash":False}
        (tree/"raw-donor-evidence.json").write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
        require(not output.exists() and not output.is_symlink(),"Output already exists")
        os.rename(tree,output)
    return result


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--archive",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True)
    p.add_argument("--source-sha",required=True)
    p.add_argument("--mode",choices=("direct","super"),required=True)
    p.add_argument("--partition",action="append",required=True)
    p.add_argument("--slot",type=int,choices=(0,1))
    a=p.parse_args()
    report=prepare(a.archive,a.output,a.source_sha,a.mode,a.partition,a.slot)
    print(report["status"],"safe_to_flash=false")


if __name__=="__main__":
    main()
