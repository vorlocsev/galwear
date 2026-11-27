#!/usr/bin/env python3
"""Test the pinned KBASE DMA attachment error guard on a disposable source copy."""
import argparse
import json
from pathlib import Path
import subprocess

from r800_kbase_abi_check import BASE, PINS, git_blob

MEM = "drivers/gpu/arm/t72x/r28p0/mali_kbase_mem_linux.c"
DMA_BLOB = "f6c094db87b857bc5a05722478e17e44eb93a5ae"
OLD = "\tif (!dma_attachment)\n\t\tgoto no_attachment;"
NEW = "\tif (IS_ERR_OR_NULL(dma_attachment))\n\t\tgoto no_attachment;"

def fragments(source):
    start = source.index("static struct kbase_va_region *kbase_mem_from_umm(")
    end = source.index("\n}\n", start)
    body = source[start:end]
    acquire = body[body.index("\tdma_buf = dma_buf_get(fd);"):
                   body.index("\t*va_pages =")]
    cleanup = body[body.index("bad_size:\n"):]
    if cleanup.strip() != ("bad_size:\n\tdma_buf_detach(dma_buf, dma_attachment);\n"
                            "no_attachment:\n\tdma_buf_put(dma_buf);\nno_buf:\n\treturn NULL;"):
        raise ValueError("Unexpected attachment cleanup")
    return acquire, cleanup

def harness(source):
    acquire, cleanup = fragments(source)
    return r'''
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#define IS_ERR_OR_NULL(p) (!(p) || (uintptr_t)(p) >= (uintptr_t)-4095)
static int mode, gets, attaches, puts_count, detaches;
static int token, attachment, device;
static struct { void *dev; } kbdev = { &device };
static struct { typeof(kbdev) *kbdev; } context = { &kbdev };
static void *dma_buf_get(int fd) {
    assert(fd==7); ++gets;
    return mode==1 ? (void *)(intptr_t)-9 : &token;
}
static void *dma_buf_attach(void *buf, void *dev) {
    assert(buf==&token && dev==&device); ++attaches;
    if (mode==2) return (void *)(intptr_t)-12;
    if (mode==3) return NULL;
    return &attachment;
}
static void dma_buf_put(void *buf) { assert(buf==&token); ++puts_count; }
static void dma_buf_detach(void *buf, void *att) {
    assert(buf==&token && att==&attachment); ++detaches;
}
static void *probe(void) {
    int fd=7;
    typeof(context) *kctx=&context;
    void *dma_buf, *dma_attachment;
''' + acquire + r'''
    if (mode==4) goto bad_size;
    return dma_attachment;
''' + cleanup + r'''
}
int main(int argc, char **argv) {
    if (argc!=2) return 2;
    mode=atoi(argv[1]);
    void *result=probe();
    if (mode==2 && result==(void *)(intptr_t)-12) return 42;
    if (mode==0) {
        assert(result==&attachment && gets==1 && attaches==1 && !puts_count && !detaches);
        dma_buf_detach(&token, result);
        dma_buf_put(&token);
    } else {
        assert(!result && gets==1 && attaches==(mode!=1));
    }
    assert(puts_count==(mode!=1) && detaches==(mode==0 || mode==4));
    puts("KBASE_DMA_GUARD_CASE_PASS");
    return 0;
}
'''

def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ("mem-source", "dma-source", "patch", "scratch"):
        p.add_argument("--"+name, type=Path, required=True)
    p.add_argument("--source-sha", required=True)
    a = p.parse_args()
    raw = a.mem_source.read_bytes()
    dma = a.dma_source.read_bytes()
    if git_blob(raw)!=PINS["mali_kbase_mem_linux.c"] or git_blob(dma)!=DMA_BLOB:
        raise ValueError("Pinned source mismatch")
    original = raw.decode()
    if original.count(OLD)!=1 or "return ERR_PTR(ret);" not in dma.decode():
        raise ValueError("Unexpected DMA attachment source")
    a.scratch.mkdir(parents=True, exist_ok=False)
    target = a.scratch/MEM
    target.parent.mkdir(parents=True)
    target.write_bytes(raw)
    for flags in (["--check"], []):
        subprocess.run(["git", "apply", *flags, "--include="+MEM, str(a.patch.resolve())],
                       cwd=a.scratch, check=True, timeout=30)
    patched = target.read_text()
    if patched!=original.replace(OLD, NEW):
        raise ValueError("Unexpected KBASE patch delta")
    for name, source in (("original", original), ("patched", patched)):
        unit = a.scratch/(name+".c")
        exe = a.scratch/name
        unit.write_text(harness(source))
        subprocess.run(["cc","-std=gnu11","-Wall","-Wextra","-Werror",str(unit),"-o",str(exe)],
                       check=True, timeout=30)
        for mode in ([2] if name=="original" else range(5)):
            result = subprocess.run([str(exe.resolve()),str(mode)],capture_output=True,text=True,timeout=5)
            expected = 42 if name=="original" else 0
            if result.returncode!=expected or (expected==0 and result.stdout.strip()!="KBASE_DMA_GUARD_CASE_PASS"):
                raise ValueError("Unexpected guard result "+name+" "+str(mode)+": "+str(result.returncode))
    report = {"status":"KBASE_DMA_ATTACH_GUARD_SYNTHETIC_ONLY","source_sha":a.source_sha,
              "kernel_sha":BASE,"original_err_ptr_reproduced":True,"patched_cases":5,
              "cases":["success","get_error","attach_err_ptr","attach_null","post_attach_failure"],
              "actual_dma_buf_import_verified":False,"kernel_compiled":False,"safe_to_flash":False}
    (a.scratch/"dma-guard-evidence.json").write_text(json.dumps(report,sort_keys=True)+"\n")
    print(json.dumps(report,sort_keys=True))

if __name__=="__main__":
    main()
