#!/usr/bin/env python3
"""Stage an audited tzlite static candidate, not a deployment-ready rootfs."""
import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import tempfile

from r800_tzlite_audit import check, MOUNTPOINTS, REQUIRED_TREES
from r800_tizen_gnss_preflight import CONFIGS, CONFIG_LIMIT, metadata
from r800_tizen_dependencies import resolve_guest, MAX_FILE, MAX_TOTAL
from r800_android_userspace_preflight import read_regular
from r800_tzlite_manifest import inventory as tree_inventory, verify as verify_manifest, MANIFEST


def guest_destination(root, name):
    p=PurePosixPath(name)
    if not p.is_absolute() or str(p)!=name or ".." in p.parts or name=="/":
        raise ValueError("Unsafe guest path")
    dest=root.joinpath(*p.parts[1:])
    for parent in dest.parents:
        if parent==root:
            break
        if parent.is_symlink():
            raise ValueError("Staging parent symlink")
    return dest


def publish(stage, output):
    # Linux atomic no-replace rename. Never fall back to replacing an output.
    libc=ctypes.CDLL(None,use_errno=True)
    rename=getattr(libc,"renameat2",None)
    if rename is None:
        raise ValueError("Atomic no-replace publication unavailable")
    rename.argtypes=(ctypes.c_int,ctypes.c_char_p,ctypes.c_int,ctypes.c_char_p,ctypes.c_uint)
    rename.restype=ctypes.c_int
    if rename(-100,os.fsencode(stage),-100,os.fsencode(output),1)!=0:
        err=ctypes.get_errno()
        raise OSError(err,os.strerror(err))


def require_candidate(report):
    if (report.get("schema")!="r800-tzlite-audit-v1"
            or report.get("status")!="TZLITE_KNOWN_STATIC_CANDIDATES_ONLY"
            or report.get("problems")!=[] or report.get("safe_to_flash") is not False):
        raise ValueError("Known tzlite component audit did not pass")


def stage(root,output):
    if os.geteuid()==0:
        raise ValueError("Run static staging as an unprivileged user")
    root=root.resolve(strict=True)
    if root==Path("/") or not root.is_dir():
        raise ValueError("Expected isolated donor tree")
    parent=output.absolute().parent.resolve(strict=True)
    output=parent/output.name
    if output.exists() or output.is_symlink() or output.is_relative_to(root):
        raise ValueError("Output must be new and outside donor tree")
    before=check(root)
    require_candidate(before)
    closure=before["dependency_evidence"]
    config=before["configuration_evidence"]["files"]
    inventory={}
    total=0
    with tempfile.TemporaryDirectory(prefix=".tzlite-candidate-",dir=parent) as tmp:
        candidate=Path(tmp)/"candidate"
        candidate.mkdir(mode=0o700)
        for guest in MOUNTPOINTS+REQUIRED_TREES:
            guest_destination(candidate,guest).mkdir(parents=True,exist_ok=True)
        for guest,item in sorted(closure["files"].items()):
            source,canonical=resolve_guest(root,guest)
            if canonical!=guest:
                raise ValueError("Canonical donor path changed")
            raw=read_regular(source,MAX_FILE)
            digest=hashlib.sha256(raw).hexdigest()
            if digest!=item["sha256"] or len(raw)!=item["bytes"]:
                raise ValueError("Donor ELF changed")
            total+=len(raw)
            if total>MAX_TOTAL:
                raise ValueError("Candidate byte budget exceeded")
            dest=guest_destination(candidate,guest)
            dest.parent.mkdir(parents=True,exist_ok=True)
            with dest.open("xb") as f:
                f.write(raw)
            mode=0o755 if source.lstat().st_mode&0o111 else 0o644
            dest.chmod(mode)
            inventory[guest]={"sha256":digest,"bytes":len(raw),"mode":oct(mode)}
        for guest in CONFIGS:
            if metadata(root,guest).get("kind")!="regular":
                raise ValueError("Donor configuration changed")
            raw=read_regular(root/guest.lstrip("/"),CONFIG_LIMIT)
            digest=hashlib.sha256(raw).hexdigest()
            if digest!=config[guest]["sha256"] or len(raw)!=config[guest]["bytes"]:
                raise ValueError("Donor configuration changed")
            total+=len(raw)
            if total>MAX_TOTAL:
                raise ValueError("Candidate byte budget exceeded")
            dest=guest_destination(candidate,guest)
            dest.parent.mkdir(parents=True,exist_ok=True)
            with dest.open("xb") as f:
                f.write(raw)
            dest.chmod(0o600)
            inventory[guest]={"sha256":digest,"bytes":len(raw),"mode":"0o600"}
        for alias,canonical in sorted(closure["aliases"].items()):
            _,actual=resolve_guest(root,alias)
            if actual!=canonical or canonical not in closure["files"]:
                raise ValueError("Donor alias changed")
            if alias==canonical:
                continue
            dest=guest_destination(candidate,alias)
            target=guest_destination(candidate,canonical)
            dest.parent.mkdir(parents=True,exist_ok=True)
            dest.symlink_to(os.path.relpath(target,dest.parent))
        after=check(candidate)
        require_candidate(after)
        for key in ("files","aliases"):
            if after["dependency_evidence"][key]!=closure[key]:
                raise ValueError("Staged ELF closure differs from source")
        if after["configuration_evidence"]["files"]!=config:
            raise ValueError("Staged configuration differs from source")
        if check(root)!=before:
            raise ValueError("Donor audit changed during staging")
        result={"schema":"r800-tzlite-static-stage-v2",
                "tree":tree_inventory(candidate),
                "status":"TZLITE_STATIC_CANDIDATE_ONLY","files":inventory,
                "aliases":closure["aliases"],"source_and_stage_audited":True,
                "full_configuration_copied":False,"plugins_complete":False,
                "ownership_preserved":False,"runtime_verified":False,
                "safe_to_flash":False}
        manifest=candidate/MANIFEST
        manifest.write_text(json.dumps(result,indent=2,sort_keys=True))
        manifest.chmod(0o600)
        digest=hashlib.sha256(manifest.read_bytes()).hexdigest()
        verify_manifest(candidate,digest)
        publish(candidate,output)
    return result


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--root",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True)
    a=p.parse_args()
    try:
        result=stage(a.root,a.output)
    except (OSError,ValueError) as exc:
        print(json.dumps({"status":"REVIEW_REQUIRED","problems":[str(exc)],"safe_to_flash":False}))
        return 2
    print(json.dumps(result,indent=2,sort_keys=True))
    return 0


if __name__=="__main__":
    raise SystemExit(main())
