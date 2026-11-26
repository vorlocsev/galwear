#!/usr/bin/env python3
"""Compare a static tzlite candidate with an externally identified raw ext4 donor."""
import argparse
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
from r800_gps_image_audit import ImageResolver
from r800_tizen_dependencies import audit
from r800_tizen_gnss_preflight import CONFIGS, CONFIG_LIMIT
from r800_tzlite_audit import TARGETS, PROGRAMS, check, closure_problems
from r800_tzlite_manifest import verify, inventory
from r800_tzlite_image_metadata import inspect_metadata
from r800_tzlite_dac import identity_candidates, summarize


def config_hashes(resolver):
    """Exact regular config paths only, no guest symlinks or arbitrary reads."""
    result={}
    for guest in CONFIGS:
        for parent in reversed(Path(guest).parents):
            if str(parent)=="/":
                continue
            record=resolver.stat_guest(str(parent))
            if record is None or record[1]!="directory":
                raise ValueError("Image configuration parent review:"+guest)
        record=resolver.stat_guest(guest)
        if record is None or record[1]!="regular" or not 0<record[2]<=CONFIG_LIMIT:
            raise ValueError("Image configuration file review:"+guest)
        inode,_,size,_=record
        dest=resolver.scratch/"member"
        command(resolver.tool,resolver.snapshot,"dump <%d> member"%inode,cwd=resolver.scratch)
        st=dest.lstat()
        if not stat.S_ISREG(st.st_mode) or st.st_size!=size:
            raise ValueError("Image configuration size mismatch:"+guest)
        raw=dest.read_bytes()
        dest.unlink()
        result[guest]={"bytes":size,"sha256":hashlib.sha256(raw).hexdigest()}
    return result


def compare(root,image,image_sha,manifest_sha):
    if not re.fullmatch(r"[0-9a-f]{64}",image_sha):
        raise ValueError("Expected lowercase image SHA-256")
    tool=shutil.which("debugfs")
    if tool is None:
        raise ValueError("Install debugfs")
    root=root.resolve(strict=True)
    image=image.absolute()
    before_manifest=verify(root,manifest_sha)
    before_tree=inventory(root)
    candidate=check(root)
    if candidate["status"]!="TZLITE_KNOWN_STATIC_CANDIDATES_ONLY" or candidate["problems"]:
        raise ValueError("Candidate known component audit did not pass")
    with tempfile.TemporaryDirectory(prefix="r800-tzlite-image-") as tmp:
        scratch=Path(tmp)
        snapshot=scratch/"donor.img"
        identity=snapshot_image(image,snapshot,image_sha)
        before=image_info(snapshot)
        if before["sha256"]!=image_sha:
            raise ValueError("Snapshot digest mismatch")
        extracted=scratch/"elf"
        extracted.mkdir()
        resolver=ImageResolver(tool,snapshot,scratch)
        closure=audit(extracted,TARGETS,resolver=resolver.resolve)
        problems=closure_problems(closure)
        staged=candidate["dependency_evidence"]
        if closure["files"]!=staged["files"]:
            problems.append("IMAGE_ELF_CLOSURE_MISMATCH")
        if closure["aliases"]!=staged["aliases"]:
            problems.append("IMAGE_ALIAS_MAPPING_MISMATCH")
        configs=config_hashes(resolver)
        if configs!=candidate["configuration_evidence"]["files"]:
            problems.append("IMAGE_CONFIGURATION_HASH_MISMATCH")
        expected_files={name:{"bytes":item["bytes"],"sha256":item["sha256"]}
                        for name,item in closure["files"].items()}
        expected_files.update(configs)
        actual_files={name:{"bytes":item["bytes"],"sha256":item["sha256"]}
                      for name,item in before_tree["entries"].items() if item["kind"]=="file"}
        if expected_files!=actual_files:
            problems.append("IMAGE_CANDIDATE_FILE_SET_MISMATCH")
        expected_aliases={name for name,canonical in closure["aliases"].items() if name!=canonical}
        actual_aliases={name for name,item in before_tree["entries"].items() if item["kind"]=="symlink"}
        if expected_aliases!=actual_aliases:
            problems.append("IMAGE_CANDIDATE_ALIAS_SET_MISMATCH")
        for name,item in resolver.files.items():
            raw=(extracted/name.lstrip("/")).read_bytes()
            if (len(raw)!=item["bytes"] or hashlib.sha256(raw).hexdigest()!=item["sha256"]
                    or closure["files"].get(name,{}).get("sha256")!=item["sha256"]):
                raise ValueError("Extracted ELF changed or not audited:"+name)
        principal=identity_candidates(candidate["configuration_evidence"]["location_account_candidates"])
        original_metadata=inspect_metadata(resolver,expected_files,principal)
        dac=summarize(original_metadata["entries"],closure,configs,PROGRAMS,principal,resolver.traces)
        st=image.lstat()
        if (st.st_dev,st.st_ino,st.st_mode,st.st_size,st.st_mtime_ns,st.st_ctime_ns)!=identity:
            raise ValueError("Donor image changed")
        if image_info(snapshot)!=before:
            raise ValueError("Donor snapshot changed")
        if verify(root,manifest_sha)!=before_manifest or inventory(root)!=before_tree:
            raise ValueError("Candidate changed during image audit")
        return {"schema":"r800-tzlite-image-binding-v1",
                "status":"REVIEW_REQUIRED" if problems else "STATIC_IMAGE_COMPONENT_MATCH_ONLY",
                "image_sha256":image_sha,"manifest_sha256":manifest_sha,
                "snapshot_verified":True,"problems":problems,
                "elf_count":len(closure["files"]),"configuration_count":len(configs),
                "alias_count":len(expected_aliases),
                "original_metadata":original_metadata,
                "dac_candidates":dac,
                "donor_authenticity_verified":False,"original_ownership_verified":False,
                "runtime_verified":False,"safe_to_flash":False}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--root",type=Path,required=True)
    p.add_argument("--image",type=Path,required=True)
    p.add_argument("--image-sha256",required=True)
    p.add_argument("--manifest-sha256",required=True)
    a=p.parse_args()
    try:
        report=compare(a.root,a.image,a.image_sha256,a.manifest_sha256)
    except (OSError,ValueError,struct.error,subprocess.SubprocessError,RecursionError) as exc:
        report={"status":"REVIEW_REQUIRED","problems":[str(exc)],"safe_to_flash":False}
    print(json.dumps(report,indent=2,sort_keys=True))
    return 2 if report["problems"] else 0


if __name__=="__main__":
    raise SystemExit(main())
