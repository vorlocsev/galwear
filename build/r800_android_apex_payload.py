#!/usr/bin/env python3
"""Preserve original runtime APEX payload and inspect selected on-disk labels.

No host mount, AVB verification, re-labeling, or activation of APEX.
"""
import argparse
import json
from pathlib import Path
import re
import subprocess
import tempfile

from r800_android_runtime_extract import extract_payload, digest, dump_file, MAX_APEX, MAX_PAYLOAD, FILES
from r800_android_rootfs_preflight import snapshot, sha
from r800_android_sepolicy_audit import audit, MAX_POLICY
from r800_android_init_dependencies import regular
from r800_android_dynamic_audit import RUNTIME, MAX_ELF, inspect_elf
from r800_android_system_ext4 import invoke, LABEL


def read_label(image, path, scratch, debugfs):
    if not re.fullmatch(r"/[A-Za-z0-9_./-]*", path) or ".." in Path(path).parts:
        raise ValueError("Unexpected APEX inode path")
    dest = scratch/"label"
    if dest.exists():
        dest.unlink()
    invoke([debugfs, "-R", f"ea_get -f {dest} {path} security.selinux", image])
    raw = snapshot(dest,1024)
    if not raw.endswith(b"\0"):
        raise ValueError("Missing NUL-terminated APEX label: "+path)
    label = raw[:-1].decode("ascii")
    if not LABEL.fullmatch(label):
        raise ValueError("Invalid APEX label: "+path)
    return label


def verify_selected(payload, staged, scratch, debugfs, readelf):
    staged = staged.resolve(strict=True)
    selected = {}
    for name in FILES:
        path = "/"+name
        label = read_label(payload,path,scratch,debugfs)
        local = scratch/"elf"
        if local.exists():
            local.unlink()
        dump_file(payload,path,local,MAX_ELF)
        info = inspect_elf(local,readelf)
        source = regular(staged,RUNTIME+"/"+name)
        if source is not None and sha(snapshot(source,MAX_ELF)) != info["sha256"]:
            raise ValueError("Staged APEX ELF differs from original payload: "+name)
        selected[path] = {"context":label,"sha256":info["sha256"],
                          "matches_staged":source is not None,"elf":info}
    for path in ("/","/bin","/lib64","/lib64/bionic"):
        selected[path] = {"context":read_label(payload,path,scratch,debugfs)}
    if not any(v.get("matches_staged") for v in selected.values()):
        raise ValueError("No staged runtime ELF linked to payload")
    return selected


def build(a):
    root = a.product_out.resolve(strict=True)
    policy = audit(root,a.checkfc)
    pol = snapshot(regular(root,policy["policy_path"]),MAX_POLICY)
    if sha(pol) != policy["policy_sha256"]:
        raise ValueError("Policy changed")
    if digest(a.apex,MAX_APEX) != a.apex_sha256:
        raise ValueError("APEX donor digest mismatch")
    if a.out.exists() or a.out.is_symlink():
        raise ValueError("Output must be new")
    with tempfile.TemporaryDirectory(prefix="galwear-apex-payload-",dir="/tmp") as tmp:
        scratch = Path(tmp)
        payload = scratch/"runtime.ext4"
        extract_payload(a.apex,payload)
        before = digest(payload,MAX_PAYLOAD)
        selected = verify_selected(payload,a.staged,scratch,a.debugfs,a.readelf)
        # Check the existing on-disk types against the same compiled policy.
        # This is NOT an assertion that a generated file_contexts is authentic.
        check = scratch/"observed_contexts"
        check.write_text("".join(re.escape("/apex/com.android.runtime"+("" if p=="/" else p))+
                                 " "+v["context"]+"\n" for p,v in sorted(selected.items())))
        policy_file = scratch/"sepolicy"
        policy_file.write_bytes(pol)
        invoke([a.checkfc.resolve(strict=True),policy_file,check])
        if digest(payload,MAX_PAYLOAD) != before or digest(a.apex,MAX_APEX) != a.apex_sha256:
            raise ValueError("APEX changed during read-only audit")
        a.out.mkdir(exist_ok=False)
        dest = a.out/"runtime.ext4"
        with dest.open("xb") as dst,payload.open("rb") as src:
            while chunk := src.read(1024*1024):
                dst.write(chunk)
        if digest(dest,MAX_PAYLOAD) != before:
            raise ValueError("Payload copy mismatch")
    return {"status":"ANDROID_RUNTIME_APEX_PAYLOAD_PRESERVED_ONLY",
            "apex_sha256":a.apex_sha256,"payload_sha256":before,
            "payload_bytes":dest.stat().st_size,"policy_sha256":policy["policy_sha256"],
            "selected_inode_labels":selected,"observed_label_types_checkfc_passed":True,
            "original_payload_bytes_preserved":True,"all_apex_inodes_audited":False,
            "apex_signature_verified":False,"avb_verified":False,
            "apex_activation_tested":False,"kernel_mount_tested":False,
            "android_init_started":False,"safe_to_flash":False}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ("apex","staged","product-out","checkfc","out","report"):
        p.add_argument("--"+name,type=Path,required=True)
    p.add_argument("--apex-sha256",required=True)
    p.add_argument("--debugfs",default="debugfs")
    p.add_argument("--readelf",default="readelf")
    a=p.parse_args()
    try:
        report=build(a)
        rc=0
    except (OSError,ValueError,KeyError,TypeError,RuntimeError,subprocess.SubprocessError) as exc:
        report={"status":"REJECT","reason":str(exc),"safe_to_flash":False}
        rc=2
    a.report.write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    print(report["status"])
    return rc

if __name__=="__main__":
    raise SystemExit(main())
