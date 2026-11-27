#!/usr/bin/env python3
"""Pinned DECON acquire wait: host-only fault injection, not real fences."""
import argparse
import json
from pathlib import Path
import re
import subprocess
from r800_kbase_abi_check import BASE, git_blob
from r800_decon_retire_guard import PATH, PIN, extract


# mode (command=1/video=0), wait result, fence status, expected return
CASES = (
    (1, 5, 1, 1), (0, 5, 1, 1),
    (1, 0, 0, -110), (1, 0, 1, -110),
    (1, 0, -5, -110), (0, 0, 0, -110),
    (1, -4, 0, -4), (1, -4, -5, -4),
    (0, -4, 1, -4), (1, 5, -5, -5),
    (1, 5, 0, -5), (0, 5, -5, 1),
)


def harness(source):
    return r'''
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#define DECON_MIPI_COMMAND_MODE 1
#define DPU_F_EVT_LOG(...) ((void)0)
#define DPU_DEBUG_FENCE(...) ((void)0)
#define decon_err(...) ((void)0)
struct decon_device {struct {int psr_mode;} dt;};
struct dma_fence {int dummy;};
struct dpu_fence_info {int dummy;};
static int wait_result,status_result,wait_calls,status_calls;
static struct dma_fence obj;
static int msecs_to_jiffies(int n) {assert(n==1500);return n;}
static int dma_fence_wait_timeout(struct dma_fence *f,bool intr,int timeout) {
    assert(f==&obj && !intr && timeout==1500);
    ++wait_calls;return wait_result;
}
static int dma_fence_get_status(struct dma_fence *f) {
    assert(f==&obj && wait_calls==1);++status_calls;return status_result;
}
static void dpu_save_fence_info(int fd,struct dma_fence *f,struct dpu_fence_info *i) {
    assert(fd==7 && f==&obj);(void)i;
}
''' + extract(source,"int decon_wait_fence(") + r'''
int main(int argc,char **argv) {
    assert(argc==5);
    struct decon_device d={.dt={atoi(argv[1])}};
    wait_result=atoi(argv[2]);status_result=atoi(argv[3]);
    int expected=atoi(argv[4]);
    int actual=decon_wait_fence(&d,&obj,7);
    assert(wait_calls==1 && status_calls==d.dt.psr_mode);
    if(actual!=expected) {
        fprintf(stderr,"expected %d got %d\n",expected,actual);
        return 42;
    }
    puts("DECON_ACQUIRE_GUARD_CASE_PASS");
    return 0;
}
'''


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ("fence-source","patch","scratch"):
        p.add_argument("--"+name,type=Path,required=True)
    p.add_argument("--source-sha",required=True)
    a=p.parse_args()
    if not re.fullmatch(r"[0-9a-f]{40}",a.source_sha):
        raise ValueError("Expected full GalWear SHA")
    raw=a.fence_source.read_bytes()
    if git_blob(raw)!=PIN:
        raise ValueError("Pinned DECON fence blob mismatch")
    a.scratch.mkdir(parents=True,exist_ok=False)
    target=a.scratch/PATH
    target.parent.mkdir(parents=True)
    target.write_bytes(raw)
    for flags in (["--check"],[]):
        subprocess.run(["git","apply",*flags,"--include="+PATH,str(a.patch.resolve())],
                       cwd=a.scratch,check=True,timeout=30)
    for name,source,cases in (("original",raw.decode(),[(1,-4,0,-4)]),
                              ("patched",target.read_text(),CASES)):
        unit=a.scratch/(name+".c")
        exe=a.scratch/name
        unit.write_text(harness(source))
        subprocess.run(["cc","-std=c11","-Wall","-Wextra","-Werror",
                        str(unit),"-o",str(exe)],check=True,timeout=30)
        for args in cases:
            result=subprocess.run([str(exe.resolve()),*map(str,args)],
                                  capture_output=True,text=True,timeout=5)
            if name=="original":
                if result.returncode!=42 or "expected -4 got 0" not in result.stderr:
                    raise ValueError("Original wait error masking not reproduced")
            elif result.returncode or result.stdout.strip()!="DECON_ACQUIRE_GUARD_CASE_PASS":
                raise ValueError("Unexpected acquire result "+str(args)+": "+result.stderr)
    report={"status":"DECON_ACQUIRE_WAIT_SYNTHETIC_ONLY","source_sha":a.source_sha,
            "kernel_sha":BASE,"source_blob":PIN,"cases":len(CASES),
            "original_error_masking_reproduced":True,"video_policy_unchanged":True,
            "real_sync_file_verified":False,"buffer_lifetime_verified":False,
            "safe_to_flash":False}
    (a.scratch/"acquire-evidence.json").write_text(json.dumps(report,sort_keys=True)+"\n")
    print(json.dumps(report,sort_keys=True))

if __name__=="__main__":
    main()
