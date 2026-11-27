#!/usr/bin/env python3
"""Pinned KBASE output fence failure ownership; extracted host-only model."""
import argparse
import json
from pathlib import Path
import re
import subprocess

from r800_kbase_abi_check import BASE, git_blob

SOURCE = "drivers/gpu/arm/t72x/r28p0/mali_kbase_sync_file.c"
PINS = {
    "mali_kbase_sync_file.c":"bb94aee3ccba70d39c27c9289114592fdddd5ff5",
    "mali_kbase_fence.h":"d7a65e0fb1c82067470f11c6664c212c299ecd7a",
    "sync_file.c":"b0d2563cde5d2ac6277087a00cf409d6640e5b6a",
}
OLD = "\tif (!sync_file) {\n\t\tdma_fence_put(fence);\n\t\tkbase_fence_out_remove(katom);"
NEW = "\tif (!sync_file) {\n#if (KERNEL_VERSION(4, 9, 67) >= LINUX_VERSION_CODE)\n\t\tdma_fence_put(fence);\n#endif\n\t\tkbase_fence_out_remove(katom);"

def function(text, signature):
    start = text.index(signature)
    return text[start:text.index("\n}\n", start)+3]

def harness(source, header):
    create = function(source, "int kbase_sync_fence_out_create(")
    remove = function(header, "static inline void kbase_fence_out_remove(")
    return r'''
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#define KERNEL_VERSION(a,b,c) (((a)<<16)|((b)<<8)|(c))
#ifndef LINUX_VERSION_CODE
#define LINUX_VERSION_CODE KERNEL_VERSION(4,19,0)
#endif
struct dma_fence { int refs; };
struct kbase_jd_atom { struct { struct dma_fence *fence; } dma_fence; };
struct sync_file { void *file; };
static struct dma_fence obj;
static struct sync_file sync;
static int mode, underflow, installed;
static struct dma_fence *kbase_fence_out_new(struct kbase_jd_atom *a) {
    if (mode==1) return NULL;
    obj.refs=1;
    a->dma_fence.fence=&obj;
    return &obj;
}
static struct dma_fence *dma_fence_get(struct dma_fence *f) {
    assert(f==&obj && f->refs>0); ++f->refs; return f;
}
static void dma_fence_put(struct dma_fence *f) {
    assert(f==&obj);
    if (f->refs<=0) ++underflow;
    --f->refs;
}
static struct sync_file *sync_file_create(struct dma_fence *f) {
    if (mode==2) return NULL;
#if LINUX_VERSION_CODE > KERNEL_VERSION(4,9,67)
    dma_fence_get(f);
#else
    assert(f==&obj && f->refs==2);
#endif
    sync.file=f;
    return &sync;
}
static int get_unused_fd_flags(int flags) { assert(flags==O_CLOEXEC); return mode==3?-EMFILE:7; }
static void fput(void *f) { dma_fence_put(f); }
static void fd_install(int fd, void *f) { assert(fd==7 && f==&obj); ++installed; }
''' + remove + create + r'''
int main(int argc, char **argv) {
    if (argc!=2) return 2;
    mode=atoi(argv[1]);
    struct kbase_jd_atom a={0};
    int rc=kbase_sync_fence_out_create(&a, -1);
    if (underflow) return 42;
    if (mode==0) {
        assert(rc==7 && installed==1 && obj.refs==2 && a.dma_fence.fence==&obj);
        kbase_fence_out_remove(&a);
        assert(obj.refs==1);
        fput(sync.file);
    } else {
        assert(rc==(mode==3?-EMFILE:-ENOMEM));
        assert(installed==0);
    }
    assert(!a.dma_fence.fence && obj.refs==0 && !underflow);
    puts("KBASE_FENCE_GUARD_CASE_PASS");
    return 0;
}
'''

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ("source-dir","patch","scratch"):
        p.add_argument("--"+name,type=Path,required=True)
    p.add_argument("--source-sha",required=True)
    a=p.parse_args()
    if not re.fullmatch(r"[0-9a-f]{40}",a.source_sha):
        raise ValueError("Expected full GalWear SHA")
    files={}
    for name,pin in PINS.items():
        raw=(a.source_dir/name).read_bytes()
        if git_blob(raw)!=pin:
            raise ValueError("Pinned source mismatch: "+name)
        files[name]=raw.decode()
    original=files["mali_kbase_sync_file.c"]
    header=files["mali_kbase_fence.h"]
    sync_create=function(files["sync_file.c"],"struct sync_file *sync_file_create(")
    if original.count(OLD)!=1 or "sync_file->fence = dma_fence_get(fence);" not in sync_create:
        raise ValueError("Unexpected fence ownership contract")
    a.scratch.mkdir(parents=True,exist_ok=False)
    target=a.scratch/SOURCE
    target.parent.mkdir(parents=True)
    target.write_text(original)
    for flags in (["--check"],[]):
        subprocess.run(["git","apply",*flags,"--include="+SOURCE,str(a.patch.resolve())],
                       cwd=a.scratch,check=True,timeout=30)
    patched=target.read_text()
    if patched!=original.replace(OLD,NEW):
        raise ValueError("Unexpected fence patch delta")
    count=0
    for variant,source,version,modes in (
        ("original",original,"KERNEL_VERSION(4,19,0)",[2]),
        ("patched",patched,"KERNEL_VERSION(4,19,0)",range(4)),
        ("legacy_model",patched,"KERNEL_VERSION(4,9,67)",range(4)),
    ):
        unit=a.scratch/(variant+".c")
        exe=a.scratch/variant
        unit.write_text(harness(source,header).replace("struct fence *", "struct dma_fence *"))
        subprocess.run(["cc","-std=gnu11","-Wall","-Wextra","-Wno-unused-parameter",
                        "-Wno-unused-function","-Werror","-DLINUX_VERSION_CODE="+version,
                        str(unit),"-o",str(exe)],check=True,timeout=30)
        for mode in modes:
            result=subprocess.run([str(exe.resolve()),str(mode)],capture_output=True,text=True,timeout=5)
            expected=42 if variant=="original" else 0
            if result.returncode!=expected or (not expected and result.stdout.strip()!="KBASE_FENCE_GUARD_CASE_PASS"):
                raise ValueError("Unexpected fence result "+variant+" "+str(mode)+": "+str(result.returncode))
            count+=not expected
    report={"status":"KBASE_FENCE_REFCOUNT_SYNTHETIC_ONLY","source_sha":a.source_sha,
            "kernel_sha":BASE,"original_underflow_reproduced":True,"patched_cases":count,
            "legacy_contract_modeled":True,"source_blobs":PINS,"kernel_compiled":False,
            "sync_file_runtime_verified":False,"gpu_hardware_verified":False,"safe_to_flash":False}
    (a.scratch/"fence-guard-evidence.json").write_text(json.dumps(report,sort_keys=True)+"\n")
    print(json.dumps(report,sort_keys=True))

if __name__=="__main__":
    main()
