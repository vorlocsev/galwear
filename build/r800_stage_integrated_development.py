#!/usr/bin/env python3
"""Assemble local same-head development components, never an installation image.

Requires the original functional kernel build directory at its build path,
and the pinned adaptation and Android layers. Reuses the development tree
assembler rather than trusting a separately editable final tree. The boot
directory is for build evidence only; no NZIT, tar, boot marker or guest run.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import tempfile

from r800_android_userspace_preflight import read_regular, MAX_CONFIG
from r800_boot_candidate import PARTITION, DT_SIZE
from r800_cpio_audit import MAX_ARCHIVE_BYTES
from r800_initramfs_spec import MAX_INIT_BYTES
from r800_development_kernel import finalize
from r800_stage_development_tree import assemble as assemble_tree
from r800_stage_adaptation_layer import valid_pin
from r800_graphics_donor_binding import checkout_sha
from r800_extract_super import require
from r800_verify_tizen_stage import unique_keys

REPORT = "development-kernel-evidence.json"
LIMIT = 4*1024**2


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def kernel_inputs(root, pin, source_sha, scratch):
    require(valid_pin(pin), "Explicit kernel evidence SHA-256 required")
    raw=read_regular(root/REPORT,LIMIT)
    require(sha(raw)==pin,"Kernel evidence pin mismatch")
    report=json.loads(raw,object_pairs_hook=unique_keys)
    require(report.get("schema")=="galwear-r800-development-kernel-v1" and
            report.get("status")=="DEVELOPMENT_KERNEL_COMPONENTS_STATIC_ONLY" and
            report.get("source_sha")==source_sha and
            report.get("boot_profile")=="DEVELOPMENT_FUNCTIONAL_UNTESTED" and
            report.get("effective_kernel_config_verified") is True and
            report.get("storage_write_capable") is True and
            all(report.get(k) is False for k in ("kernel_initramfs_symbols_verified",
                "kernel_boot_tested","android_handover_tested","hardware_tested","safe_to_flash")),
            "Expected same-head functional kernel evidence")
    archive=root/"obj/usr/initramfs_data.cpio.gz"
    if not archive.exists() and not archive.is_symlink():
        archive=root/"obj/usr/initramfs_data.cpio"
    inputs={
        "Image":(root/"obj/arch/arm64/boot/Image",PARTITION,report["components"]["kernel_sha256"]),
        "r800.dtb":(root/"r800.dtb",DT_SIZE,report["components"]["dtb_sha256"]),
        "effective.config":(root/"obj/.config",MAX_CONFIG,report["config_sha256"]),
        "init":(root/"initramfs/init",MAX_INIT_BYTES,report["init_sha256"]),
        "initramfs.generated":(archive,MAX_ARCHIVE_BYTES,report["generated_cpio"]["archive_sha256"]),
    }
    require(all(p.resolve(strict=True)==p and valid_pin(h) for p,_,h in inputs.values()),
            "Canonical pinned kernel component paths required")
    check=finalize(root/"initramfs",inputs["effective.config"][0],inputs["Image"][0],
                   inputs["r800.dtb"][0],archive,scratch/"kernel-rechecked.json",source_sha)
    require(check==report,"Kernel evidence differs from recomputed result")
    return raw,report,inputs


def assemble(kernel,kernel_sha,adaptation,adaptation_sha,android,android_sha,output,source_sha):
    checkout_sha(source_sha)
    kernel,adaptation,android=(Path(p).absolute() for p in (kernel,adaptation,android))
    require(all(p.resolve(strict=True)==p and p.is_dir() for p in (kernel,adaptation,android)),
            "Canonical local build directories required")
    output=Path(output).absolute()
    repo=Path(__file__).resolve().parents[1]
    require(not output.exists() and not output.is_symlink() and
            not any(output.resolve().is_relative_to(p) for p in (repo,kernel,adaptation,android)),
            "Fresh output outside input trees required")
    with tempfile.TemporaryDirectory(dir=output.parent,prefix="r800-integrated-") as tmp:
        work=Path(tmp)
        raw,report,inputs=kernel_inputs(kernel,kernel_sha,source_sha,work)
        tree=work/"tree"
        userspace=assemble_tree(adaptation,adaptation_sha,android,android_sha,tree,source_sha)
        require(userspace["status"]=="ANDROID_DEVICE_DEVELOPMENT_TREE_STAGED_ONLY" and
                userspace["source_sha"]==source_sha and userspace["safe_to_flash"] is False,
                "Unexpected userspace scope")
        boot=tree/"development-boot"
        boot.mkdir()
        rows={}
        for name,(path,limit,pin) in sorted(inputs.items()):
            blob=read_regular(path,limit)
            require(sha(blob)==pin,"Kernel component changed: "+name)
            dest=boot/name
            with dest.open("xb") as stream:
                stream.write(blob)
            dest.chmod(0o400)
            require(read_regular(dest,limit)==blob,"Copied kernel component mismatch")
            rows["development-boot/"+name]={"bytes":len(blob),"sha256":pin,"mode":"0o400"}
        require(read_regular(kernel/REPORT,LIMIT)==raw,"Kernel evidence changed")
        for name,(path,limit,pin) in inputs.items():
            require(sha(read_regular(path,limit))==pin,"Kernel input changed: "+name)
        userspace_raw=read_regular(tree/"development-tree-evidence.json",LIMIT)
        require(json.loads(userspace_raw,object_pairs_hook=unique_keys)==userspace,
                "Userspace report changed")
        checkout_sha(source_sha)
        result={"schema":"galwear-r800-integrated-development-v1",
                "status":"FUNCTIONAL_KERNEL_AND_ANDROID_TREE_STAGED_ONLY",
                "source_sha":source_sha,"kernel_evidence_sha256":kernel_sha,
                "userspace_evidence_sha256":sha(userspace_raw),
                "kernel_files":rows,"userspace_files":len(userspace["files"]),
                "userspace_bytes":userspace["total_bytes"],
                "kernel_boot_profile":report["boot_profile"],
                "effective_config_role":"BUILD_EVIDENCE_ONLY_ORIGINAL_ARCHIVE_PATH",
                "missing_inputs_and_gates":userspace["missing_inputs_and_gates"],
                "storage_write_capable":True,"boot_container_created":False,
                "payload_complete":False,"wear_os_verified":False,
                "android_handover_tested":False,"hardware_tested":False,"safe_to_flash":False}
        (tree/"integrated-development-evidence.json").write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
        require(not output.exists() and not output.is_symlink(),"Output already exists")
        os.rename(tree,output)
    return result


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ("kernel","adaptation","android","output"):
        p.add_argument("--"+name,type=Path,required=True)
    for name in ("kernel-sha256","adaptation-sha256","android-sha256","source-sha"):
        p.add_argument("--"+name,required=True)
    a=p.parse_args()
    report=assemble(a.kernel,a.kernel_sha256,a.adaptation,a.adaptation_sha256,
                    a.android,a.android_sha256,a.output,a.source_sha)
    print(report["status"],"safe_to_flash=false")


if __name__=="__main__":
    main()
