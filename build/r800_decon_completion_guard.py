#!/usr/bin/env python3
"""Pinned DECON completion order and null retire guard; host-only model."""
import argparse
import json
from pathlib import Path
import re
import subprocess
from r800_kbase_abi_check import BASE, git_blob
from r800_decon_buffer_guard import SOURCE, PIN
from r800_decon_retire_guard import extract


def completion(source):
    fn=extract(source,"static void decon_update_regs(")
    start=fn.index("fence_err:\n")
    end=fn.index("DPU_EVENT_LOG(DPU_EVT_FENCE_RELEASE",start)
    return fn[start+len("fence_err:\n"):end]


def harness(source):
    return r'''
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
struct decon_rect {int x;};
struct dma_fence {int refs,signaled;};
struct decon_reg_data {struct dma_fence *retire_fence;};
struct decon_device {
    struct {int enabled;struct decon_rect prev_up_region,back_up_region;} win_up;
};
static int releases,signals,puts_count,null_calls;
static struct dma_fence obj;
static void decon_release_old_bufs(struct decon_device *d,struct decon_reg_data *r,int *buf,int *counts) {
    (void)d;(void)r;(void)buf;(void)counts;assert(!signals && !puts_count);++releases;
}
static void decon_signal_fence(struct decon_device *d,struct dma_fence *f) {
    (void)d;
    if(!f){++null_calls;return;}
    assert(releases==1 && f==&obj && f->refs==2 && !f->signaled && !puts_count);
    ++signals;f->signaled=1;
}
static void dma_fence_put(struct dma_fence *f) {
    if(!f){++null_calls;return;}
    assert(f==&obj && f->signaled && f->refs==2 && signals==1);
    ++puts_count;--f->refs;
}
static void finish(struct decon_device *decon,struct decon_reg_data *regs,bool winup_rollback) {
    int old_dma_bufs[3]={0},old_plane_cnt[3]={0};
''' + completion(source) + r'''
}
int main(int argc,char **argv) {
    assert(argc==4);
    int has=atoi(argv[1]),rollback=atoi(argv[2]),enabled=atoi(argv[3]);
    struct decon_device d={.win_up={enabled,{11},{7}}};
    struct decon_reg_data r={.retire_fence=has?&obj:NULL};
    obj.refs=has?2:0;
    finish(&d,&r,rollback);
    assert(releases==1 && d.win_up.prev_up_region.x==(rollback && enabled?7:11));
    if(null_calls)return 42;
    assert(signals==has && puts_count==has && obj.refs==has && obj.signaled==has);
    puts("DECON_COMPLETION_GUARD_CASE_PASS");
    return 0;
}
'''


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ("core-source","patch","scratch"):
        p.add_argument("--"+name,type=Path,required=True)
    p.add_argument("--source-sha",required=True)
    a=p.parse_args()
    if not re.fullmatch(r"[0-9a-f]{40}",a.source_sha):
        raise ValueError("Expected full GalWear SHA")
    raw=a.core_source.read_bytes()
    if git_blob(raw)!=PIN:
        raise ValueError("Pinned DECON core blob mismatch")
    a.scratch.mkdir(parents=True,exist_ok=False)
    target=a.scratch/SOURCE
    target.parent.mkdir(parents=True)
    target.write_bytes(raw)
    for flags in (["--check"],[]):
        subprocess.run(["git","apply",*flags,"--include="+SOURCE,str(a.patch.resolve())],
                       cwd=a.scratch,check=True,timeout=30)
    cases=[(has,rollback,enabled) for has in (0,1) for rollback in (0,1) for enabled in (0,1)]
    for name,source,rows in (("original",raw.decode(),[(0,0,1)]),
                              ("patched",target.read_text(),cases)):
        unit=a.scratch/(name+".c")
        exe=a.scratch/name
        unit.write_text(harness(source))
        subprocess.run(["cc","-std=c11","-Wall","-Wextra","-Werror",str(unit),"-o",str(exe)],
                       check=True,timeout=30)
        for args in rows:
            result=subprocess.run([str(exe.resolve()),*map(str,args)],capture_output=True,text=True,timeout=5)
            if name=="original":
                if result.returncode!=42:
                    raise ValueError("Original null retire calls not reproduced")
            elif result.returncode or result.stdout.strip()!="DECON_COMPLETION_GUARD_CASE_PASS":
                raise ValueError("Unexpected completion result "+str(args)+": "+result.stderr)
    report={"status":"DECON_COMPLETION_ORDER_SYNTHETIC_ONLY","source_sha":a.source_sha,
            "kernel_sha":BASE,"source_blob":PIN,"cases":len(cases),
            "original_null_calls_reproduced":True,"shared_fence_status_unchanged":True,
            "real_sync_file_verified":False,"hardware_tested":False,"safe_to_flash":False}
    (a.scratch/"completion-evidence.json").write_text(json.dumps(report,sort_keys=True)+"\n")
    print(json.dumps(report,sort_keys=True))

if __name__=="__main__":
    main()
