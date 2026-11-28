#!/usr/bin/env python3
"""Compile and stage the historical functional R800 init, without kernel build.

The functional init mounts p17 read-write and executes start.sh on hardware.
Never execute it in this host pipeline. The output is not a boot image.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

from r800_android_userspace_preflight import read_regular, parse_kernel_config, REQUIRED_CONFIG, MAX_CONFIG
from r800_graphics_donor_binding import checkout_sha
from r800_initramfs_spec import validate_init, MAX_INIT_BYTES
from r800_cpio_audit import inspect_cpio
from r800_android_rootfs_preflight import newc
from r800_extract_super import require

REQUIRED = {**REQUIRED_CONFIG, **{k:"y" for k in (
    "CONFIG_MMC","CONFIG_MMC_BLOCK","CONFIG_MMC_DW","CONFIG_MMC_DW_EXYNOS",
    "CONFIG_BLK_DEV_INITRD","CONFIG_PROC_FS","CONFIG_SYSFS")}}
SOURCE_CONFIG = 'CONFIG_INITRAMFS_SOURCE="/root/initramfs/list.txt"'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def check_config(raw):
    values = parse_kernel_config(raw)
    require(all(values.get(k)==v for k,v in REQUIRED.items()),
            "Development kernel prerequisites missing: "+", ".join(
                k for k,v in REQUIRED.items() if values.get(k)!=v))
    require(values.get("CONFIG_INITRAMFS_SOURCE")=='"/root/initramfs/list.txt"',
            "Unexpected baseline initramfs source")
    return values


def build(output, source_sha):
    checkout_sha(source_sha)
    repo=Path(__file__).resolve().parents[1]
    output=Path(output).absolute()
    require(not output.exists() and not output.is_symlink() and
            not output.resolve().is_relative_to(repo),"Fresh output outside checkout required")
    paths=("src/initramfs/init.c","src/initramfs/build.sh","src/kernel/r800.config")
    original={n:read_regular(repo/n,MAX_CONFIG) for n in paths}
    check_config(original[paths[2]])
    with tempfile.TemporaryDirectory(dir=output.parent,prefix="r800-development-init-") as tmp:
        work=Path(tmp)
        built=work/"compiled"
        env={**os.environ,"LC_ALL":"C","TZ":"UTC","SOURCE_DATE_EPOCH":"0"}
        for name in ("LD_PRELOAD","LD_LIBRARY_PATH","LD_AUDIT","ENV","BASH_ENV","CCC_OVERRIDE_OPTIONS"):
            env.pop(name,None)
        subprocess.run(["sh",str(repo/paths[1]),str(built)],env=env,check=True,timeout=120)
        binary=read_regular(built/"init",MAX_INIT_BYTES)
        info=validate_init(built/"init")
        require(info["sha256"]==sha(binary),"Compiled init changed")
        tree=work/"result"
        tree.mkdir()
        (tree/"init").write_bytes(binary)
        (tree/"init").chmod(0o755)
        entries=[("dev",(0o040755,b"",0,0)),("dev/console",(0o020600,b"",5,1)),
                 ("proc",(0o040555,b"",0,0)),("sys",(0o040555,b"",0,0)),
                 ("data",(0o040755,b"",0,0)),("init",(0o100755,binary,0,0))]
        archive=newc(entries)
        (tree/"initramfs.cpio").write_bytes(archive)
        cpio=inspect_cpio(tree/"initramfs.cpio",tree/"init")
        require(cpio["archive_sha256"]==sha(archive) and
                cpio["embedded_init_sha256"]==sha(binary),"Generated CPIO mismatch")
        # Keep a relocatable template. The final kernel build must explicitly
        # substitute its private absolute archive path and verify olddefconfig.
        config=original[paths[2]].decode("utf-8")
        require(config.count(SOURCE_CONFIG)==1,"Unexpected baseline config")
        config=config.replace(SOURCE_CONFIG,'CONFIG_INITRAMFS_SOURCE="@DEVELOPMENT_CPIO@"')
        (tree/"development.config.in").write_text(config)
        require(all(read_regular(repo/n,MAX_CONFIG)==raw for n,raw in original.items()),
                "Tracked source changed during build")
        checkout_sha(source_sha)
        files={n:{"sha256":sha((tree/n).read_bytes()),"bytes":(tree/n).stat().st_size}
               for n in ("init","initramfs.cpio","development.config.in")}
        report={"schema":"galwear-r800-development-initramfs-v1",
                "status":"FUNCTIONAL_INIT_COMPILED_CPIO_STAGED_ONLY",
                "source_sha":source_sha,"boot_profile":"DEVELOPMENT_FUNCTIONAL_UNTESTED",
                "source_sha256":{n:sha(raw) for n,raw in original.items()},
                "files":files,"init":info,"cpio":cpio,
                "required_baseline_config":REQUIRED,
                "handover_target":"/data/r800dev/start.sh",
                "storage_write_capable":True,"effective_kernel_config_verified":False,
                "kernel_compiled":False,"init_executed":False,"android_handover_tested":False,
                "hardware_tested":False,"safe_to_flash":False}
        (tree/"development-initramfs-evidence.json").write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
        require(not output.exists() and not output.is_symlink(),"Output already exists")
        os.rename(tree,output)
    return report


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output",type=Path,required=True)
    p.add_argument("--source-sha",required=True)
    a=p.parse_args()
    print(build(a.output,a.source_sha)["status"],"safe_to_flash=false")


if __name__=="__main__":
    main()
