#!/usr/bin/env python3
"""Stage only the audited subset of an extended tzlite review manifest, offline."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import struct
import subprocess
import tempfile

from r800_extract_ext4 import command, snapshot_image, image_info
from r800_gps_image_audit import ImageResolver
from r800_tzlite_legacy_image_scope import inspect_snapshot
from r800_tzlite_extra_plugins import check
from r800_tzlite_extended_manifest import build
from r800_tzlite_metadata_plan import digest
from r800_tzlite_audit import TARGETS, MOUNTPOINTS, REQUIRED_TREES, closure_problems
from r800_tizen_dependencies import audit
from r800_tizen_gnss_preflight import CONFIGS, CONFIG_LIMIT, config_evidence
from r800_tzlite_image_metadata import parse_inode
from r800_tzlite_image_xattrs import check_diagnostics
from r800_tzlite_manifest import inventory, MANIFEST, MAX_MANIFEST, read_file
from r800_stage_tzlite import guest_destination, publish


def stage(image,output,image_sha,review_sha):
    if os.geteuid()==0:
        raise ValueError("Run extended staging as an unprivileged user")
    if any(not re.fullmatch(r"[0-9a-f]{64}",v) for v in (image_sha,review_sha)):
        raise ValueError("Expected lowercase image and review manifest digests")
    tool=shutil.which("debugfs")
    if not tool:
        raise ValueError("Install debugfs")
    image=image.absolute()
    parent=output.absolute().parent.resolve(strict=True)
    output=parent/output.name
    if output.exists() or output.is_symlink():
        raise ValueError("Output must be new")
    with tempfile.TemporaryDirectory(prefix=".tzlite-extended-",dir=parent) as tmp:
        scratch=Path(tmp)
        snapshot=scratch/"donor.img"
        identity=snapshot_image(image,snapshot,image_sha)
        before=image_info(snapshot)
        if before["sha256"]!=image_sha:
            raise ValueError("Snapshot digest mismatch")
        resolver=ImageResolver(tool,snapshot,scratch)
        scope=inspect_snapshot(resolver)
        plugins=check(resolver,scope)
        if plugins["problems"]:
            scope["problems"]=sorted(set(scope["problems"]+["EXTRA_PLUGIN_CLOSURE_REVIEW"]))
            scope["status"]="LEGACY_SCOPE_REVIEW_REQUIRED"
        review=build(image_sha,scope,plugins)
        if digest(review)!=review_sha:
            raise ValueError("Extended review manifest SHA-256 mismatch")
        if review["status"]!="REVIEW_REQUIRED" or plugins["problems"]:
            raise ValueError("Extended plugin closure did not pass")
        closure=plugins["dependency_evidence"]
        files={n:v for n,v in review["files"].items() if v["category"] in ("AUDITED_ELF","KNOWN_CONFIG")}
        if set(files)!=set(closure["files"])|set(CONFIGS):
            raise ValueError("Extended audited subset incomplete")
        aliases=review["aliases"]
        dirs=set(MOUNTPOINTS+REQUIRED_TREES)
        for name in set(files)|set(aliases)|set(dirs):
            dirs.update(str(p) for p in PurePosixPath(name).parents if str(p)!="/")
        if dirs&(set(files)|set(aliases)):
            raise ValueError("Extended staging parent conflict")
        candidate=scratch/"candidate"
        candidate.mkdir(mode=0o700)
        for name in sorted(dirs):
            guest_destination(candidate,name).mkdir(mode=0o755,parents=True,exist_ok=True)
        for name,record in sorted(files.items()):
            # Only canonical regular paths. Configs must have no link parents;
            # ELF files were resolved in the same immutable private snapshot.
            for path in reversed(PurePosixPath(name).parents):
                if str(path)=="/":
                    continue
                item=resolver.stat_guest(str(path))
                if item is None or item[1]!="directory":
                    raise ValueError("Extended staging source parent review:"+name)
            item=resolver.stat_guest(name)
            if item is None or item[1]!="regular" or item[2]!=record["bytes"]:
                raise ValueError("Extended staging source mismatch:"+name)
            inode,kind,size,_=item
            metadata=command(tool,snapshot,"stat <%d>"%inode)
            check_diagnostics(metadata.stderr)
            meta=parse_inode(metadata.stdout,inode,kind)
            if meta["links"]!=1:
                raise ValueError("Extended staging source hardlink review:"+name)
            dest=guest_destination(candidate,name)
            if record["category"]=="AUDITED_ELF":
                source=scratch/"plugin-elf"/name.lstrip("/")
                raw=read_file(source,size,capture=True)[1]
                mode=0o755 if int(meta["mode"],8)&0o111 else 0o644
            else:
                if not 0<size<=CONFIG_LIMIT:
                    raise ValueError("Extended config size review:"+name)
                member=scratch/"stage-member"
                try:
                    result=command(tool,snapshot,"dump <%d> stage-member"%inode,cwd=scratch)
                    check_diagnostics(result.stderr)
                    raw=read_file(member,CONFIG_LIMIT,capture=True)[1]
                finally:
                    member.unlink(missing_ok=True)
                mode=0o600
            if len(raw)!=size or hashlib.sha256(raw).hexdigest()!=record["sha256"]:
                raise ValueError("Extended staging file hash mismatch:"+name)
            with dest.open("xb") as stream:
                stream.write(raw)
            dest.chmod(mode)
        for name,item in sorted(aliases.items()):
            dest=guest_destination(candidate,name)
            target=guest_destination(candidate,item["canonical"])
            dest.symlink_to(os.path.relpath(target,dest.parent))
        targets=tuple(dict.fromkeys(TARGETS+tuple(plugins["candidates"])))
        after=audit(candidate,targets)
        if closure_problems(after) or any(after[k]!=closure[k] for k in ("files","aliases","symbol_candidates","relocation_review_objects")):
            raise ValueError("Extended staged ELF closure differs from source")
        config=config_evidence(candidate)
        if config["problems"] or config["files"]!={n:{k:files[n][k] for k in ("bytes","sha256")} for n in CONFIGS}:
            raise ValueError("Extended staged configuration review")
        tree=inventory(candidate)
        if set(tree["entries"])!=set(files)|set(aliases)|dirs:
            raise ValueError("Extended staged tree contains unexpected entries")
        for name,record in files.items():
            entry=tree["entries"][name]
            if any(entry[k]!=record[k] for k in ("bytes","sha256")):
                raise ValueError("Extended staged inventory differs")
        st=image.lstat()
        if (st.st_dev,st.st_ino,st.st_mode,st.st_size,st.st_mtime_ns,st.st_ctime_ns)!=identity or image_info(snapshot)!=before:
            raise ValueError("Donor changed during extended staging")
        report={"schema":"r800-tzlite-extended-stage-v1","status":"EXTENDED_STATIC_CANDIDATE_ONLY",
                "image_sha256":image_sha,"review_manifest_sha256":review_sha,
                "tree":tree,"included_files":sorted(files),
                "excluded_unreviewed_data":sorted(set(review["files"])-set(files)),
                "review_items":review["review_items"],
                "source_and_stage_audited":True,"full_configuration_copied":False,
                "plugins_complete":False,"ownership_preserved":False,
                "runtime_verified":False,"safe_to_flash":False}
        manifest=candidate/MANIFEST
        manifest.write_text(json.dumps(report,indent=2,sort_keys=True))
        manifest.chmod(0o600)
        info,_=read_file(manifest,MAX_MANIFEST)
        if inventory(candidate)!=tree:
            raise ValueError("Extended stage changed before publication")
        publish(candidate,output)
        return dict(report,stage_manifest_sha256=info["sha256"])


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--image",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True)
    p.add_argument("--image-sha256",required=True)
    p.add_argument("--review-sha256",required=True)
    a=p.parse_args()
    try:
        report=stage(a.image,a.output,a.image_sha256,a.review_sha256)
    except (OSError,ValueError,struct.error,subprocess.SubprocessError,RecursionError) as exc:
        report={"status":"REVIEW_REQUIRED","problems":[str(exc)],"safe_to_flash":False}
    print(json.dumps(report,indent=2,sort_keys=True))
    return 2 if report["status"]=="REVIEW_REQUIRED" else 0


if __name__=="__main__":
    raise SystemExit(main())
