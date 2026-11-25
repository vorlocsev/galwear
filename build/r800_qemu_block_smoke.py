#!/usr/bin/env python3
"""Create two synthetic EXT4 files and actually boot the generic block probe.

Does not use AOSP, Android images, production policy, hardware or host mounts.
"""
import argparse
import json
from pathlib import Path
import subprocess

import r800_qemu_readonly_disks as disk
from r800_android_runtime_extract import digest
from r800_android_system_ext4 import invoke

SIZE = 16*1024*1024


def run(a):
    a.fixture_dir.mkdir(exist_ok=False)
    records = []
    for i,name in enumerate(("system","runtime")):
        path = a.fixture_dir/(name+".ext4")
        with path.open("xb") as f:
            f.truncate(SIZE)
        invoke([a.mke2fs,"-F","-t","ext4","-b","4096","-I","256","-m","0",
                "-O","none,extent,filetype,dir_index,ext_attr,sparse_super,large_file",
                path],timeout=120)
        invoke([a.e2fsck,"-f","-n",path],timeout=120)
        records.append({"name":name,"path":path.resolve(),"sha256":digest(path,SIZE),
                        "bytes":SIZE,"manifest_slot":"vd"+chr(ord("a")+i)})
    evidence = disk.run_disks(a,None,records,synthetic=True)
    if evidence["status"] != "VIRT_SYNTHETIC_READONLY_BLOCK_MOUNTS_ONLY":
        raise ValueError("Wrong synthetic experiment status")
    return {**evidence,"aosp_used":False,"android_images_used":False,
            "synthetic_disk_count":len(records),"safe_to_flash":False}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ("kernel","baseline","config-evidence","init","compile-evidence",
                 "fixture-dir","out-dir","report"):
        p.add_argument("--"+name,type=Path,required=True)
    p.add_argument("--mke2fs",default="mke2fs")
    p.add_argument("--e2fsck",default="e2fsck")
    a=p.parse_args()
    try:
        result=run(a)
        rc=0
    except (OSError,ValueError,KeyError,TypeError,AttributeError,RuntimeError,subprocess.SubprocessError) as exc:
        result={"status":"REJECT","reason":str(exc),"safe_to_flash":False}
        rc=2
    a.report.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
    print(result["status"])
    return rc

if __name__=="__main__":
    raise SystemExit(main())
