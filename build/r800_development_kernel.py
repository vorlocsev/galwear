#!/usr/bin/env python3
"""Bind a development initramfs to an effective kernel config and compiled Image."""
import argparse
import hashlib
import json
from pathlib import Path
import re

from r800_android_userspace_preflight import read_regular, parse_kernel_config, MAX_CONFIG
from r800_development_initramfs import REQUIRED, SOURCE_CONFIG
from r800_cpio_audit import inspect_cpio, MAX_ARCHIVE_BYTES
from r800_initramfs_spec import MAX_INIT_BYTES
from r800_boot_candidate import component_evidence, PARTITION, DT_SIZE
from r800_graphics_donor_binding import checkout_sha
from r800_extract_super import require
from r800_verify_tizen_stage import unique_keys

PLACEHOLDER = 'CONFIG_INITRAMFS_SOURCE="@DEVELOPMENT_CPIO@"'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def validate_initramfs(root, source_sha):
    repo = Path(__file__).resolve().parents[1]
    report = json.loads(read_regular(root/"development-initramfs-evidence.json", 1024*1024),
                        object_pairs_hook=unique_keys)
    require(report.get("schema") == "galwear-r800-development-initramfs-v1" and
            report.get("status") == "FUNCTIONAL_INIT_COMPILED_CPIO_STAGED_ONLY" and
            report.get("source_sha") == source_sha and
            report.get("storage_write_capable") is True and
            report.get("boot_profile") == "DEVELOPMENT_FUNCTIONAL_UNTESTED" and
            all(report.get(k) is False for k in ("kernel_compiled","init_executed",
                                                 "android_handover_tested","safe_to_flash")),
            "Expected same-head functional development initramfs")
    require(set(report["files"]) == {"init","initramfs.cpio","development.config.in"},
            "Unexpected development initramfs inventory")
    for name, limit in (("init",MAX_INIT_BYTES),("initramfs.cpio",MAX_ARCHIVE_BYTES),
                        ("development.config.in",MAX_CONFIG)):
        raw = read_regular(root/name,limit)
        require(report["files"][name] == {"sha256":sha(raw),"bytes":len(raw)},
                "Development initramfs file changed: "+name)
    for name in ("src/initramfs/init.c","src/initramfs/build.sh","src/kernel/r800.config"):
        require(report["source_sha256"][name] == sha(read_regular(repo/name,MAX_CONFIG)),
                "Functional init source pin mismatch")
    baseline = read_regular(repo/"src/kernel/r800.config",MAX_CONFIG).decode("utf-8")
    template = read_regular(root/"development.config.in",MAX_CONFIG).decode("utf-8")
    require(baseline.count(SOURCE_CONFIG)==1 and template==baseline.replace(SOURCE_CONFIG,PLACEHOLDER),
            "Development config template differs from tracked baseline")
    require(inspect_cpio(root/"initramfs.cpio",root/"init") == report["cpio"],
            "Development archive evidence changed")
    return report, template


def archive_path(root):
    archive = root/"initramfs.cpio"
    path = str(archive.absolute())
    require(archive.resolve(strict=True)==archive.absolute() and
            re.fullmatch(r"/[A-Za-z0-9_./+-]+",path), "Unsafe development CPIO path")
    return path


def check_effective(raw, path):
    values = parse_kernel_config(raw)
    missing = [k for k,v in REQUIRED.items() if values.get(k)!=v]
    require(not missing,"Effective kernel prerequisites missing: "+", ".join(missing))
    require(values.get("CONFIG_INITRAMFS_SOURCE")=='"'+path+'"',
            "Effective initramfs source differs")
    return values


def prepare(root, config, source_sha):
    checkout_sha(source_sha)
    report,template=validate_initramfs(root,source_sha)
    path=archive_path(root)
    raw=template.replace(PLACEHOLDER,'CONFIG_INITRAMFS_SOURCE="'+path+'"').encode()
    check_effective(raw,path)
    require(config.name==".config" and not config.resolve().is_relative_to(
        Path(__file__).resolve().parents[1]),"Disposable O= .config required")
    with config.open("xb") as stream:
        stream.write(raw)


def verify(root, config, source_sha):
    checkout_sha(source_sha)
    validate_initramfs(root,source_sha)
    raw=read_regular(config,MAX_CONFIG)
    check_effective(raw,archive_path(root))
    return raw


def finalize(root, config, image, dtb, archive, output, source_sha):
    raw_config=verify(root,config,source_sha)
    report,_=validate_initramfs(root,source_sha)
    kernel=read_regular(image,PARTITION)
    device_tree=read_regular(dtb,DT_SIZE)
    generated=read_regular(archive,MAX_ARCHIVE_BYTES)
    cpio=inspect_cpio(archive,root/"init")
    require(cpio["archive_sha256"]==sha(generated) and
            cpio["newc_sha256"]==report["cpio"]["newc_sha256"],
            "Kernel-generated CPIO differs from functional archive")
    offset=kernel.find(generated,64)
    require(offset>=0 and kernel.find(generated,offset+1)<0,
            "Expected unique generated CPIO bytes in Image")
    components=component_evidence(device_tree,kernel)
    require(read_regular(image,PARTITION)==kernel and read_regular(dtb,DT_SIZE)==device_tree and
            read_regular(archive,MAX_ARCHIVE_BYTES)==generated and verify(root,config,source_sha)==raw_config,
            "Kernel build outputs changed during verification")
    result={"schema":"galwear-r800-development-kernel-v1",
            "status":"DEVELOPMENT_KERNEL_COMPONENTS_STATIC_ONLY","source_sha":source_sha,
            "boot_profile":"DEVELOPMENT_FUNCTIONAL_UNTESTED",
            "components":components,"config_sha256":sha(raw_config),
            "init_sha256":report["init"]["sha256"],"generated_cpio":cpio,
            "exact_cpio_byte_offset":offset,"effective_kernel_config_verified":True,
            "storage_write_capable":True,"kernel_initramfs_symbols_verified":False,
            "kernel_boot_tested":False,"android_handover_tested":False,
            "hardware_tested":False,"safe_to_flash":False}
    with output.open("x",encoding="utf-8") as stream:
        json.dump(result,stream,indent=2,sort_keys=True)
        stream.write("\n")
    return result


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("mode",choices=("prepare","verify","finalize"))
    p.add_argument("--initramfs",type=Path,required=True)
    p.add_argument("--config",type=Path,required=True)
    p.add_argument("--source-sha",required=True)
    for name in ("image","dtb","archive","output"):
        p.add_argument("--"+name,type=Path)
    a=p.parse_args()
    if a.mode=="prepare":
        prepare(a.initramfs,a.config,a.source_sha)
    elif a.mode=="verify":
        verify(a.initramfs,a.config,a.source_sha)
    else:
        require(all(getattr(a,n) is not None for n in ("image","dtb","archive","output")),
                "Compiled outputs required")
        print(finalize(a.initramfs,a.config,a.image,a.dtb,a.archive,a.output,a.source_sha)["status"])


if __name__=="__main__":
    main()
