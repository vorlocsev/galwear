#!/usr/bin/env python3
"""Pinned DECON retire/reservation functions: host-only failure injection."""
import argparse
import json
from pathlib import Path
import re
import subprocess

from r800_kbase_abi_check import BASE, git_blob

PATH = "drivers/video/fbdev/exynos/dpu30/fence.c"
PIN = "09199f9171d98662e8637166c52bbc3c938fc093"

def extract(source, signature):
    start = source.index(signature)
    return source[start:source.index("\n}\n",start)+3]

def harness(source):
    return r'''
#define _GNU_SOURCE 1
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#define FD_TRY_CNT 3
#define VALID_FD_VAL 3
#define GFP_KERNEL 0
#define decon_warn(...) ((void)0)
#define decon_err(...) ((void)0)
#define DPU_F_EVT_LOG(...) ((void)0)
#define DPU_DEBUG_FENCE(...) ((void)0)
#define DECON_WIN_STATE_BUFFER 2
struct dma_fence {int refs;};
struct file {int refs;};
struct sync_file {struct file *file;};
struct dpu_fence_info {int dummy;};
struct decon_device {
    struct {int lock,context,timeline;} fence;
    struct {int max_win;} dt;
};
struct decon_win_config_data {struct {int state,rel_fence;} config[3];};
static int decon_fence_ops;
static int mode, calls, puts_count, logged, closed, fail_after, err_code, low_count;
static int state[32];
static struct dma_fence obj;
static struct file file;
static struct sync_file sync={&file};
static int get_unused_fd_flags(int flags) {
    assert(flags==O_CLOEXEC);
    int n=calls++;
    if(n==fail_after)return err_code;
    int fd=n<low_count?n:7+n-low_count;
    assert(fd<32 && !state[fd]);state[fd]=1;return fd;
}
static void put_unused_fd(int fd) {assert(state[fd]==1);state[fd]=0;++puts_count;}
static void *kzalloc(size_t n,int flags) {(void)n;(void)flags;return mode==1?NULL:&obj;}
static int atomic_inc_return(int *v) {return ++*v;}
static void dma_fence_init(struct dma_fence *f,int *ops,int *lock,int ctx,int seq) {
    (void)ops;(void)lock;(void)ctx;(void)seq;assert(f==&obj);f->refs=1;
}
static void dma_fence_put(struct dma_fence *f) {assert(f==&obj && f->refs>0);--f->refs;}
static struct sync_file *sync_file_create(struct dma_fence *f) {
    assert(f==&obj && f->refs==1);
    if(mode==2)return NULL;
    ++f->refs;file.refs=1;return &sync;
}
static void fput(struct file *f) {assert(f==&file && f->refs==1);--f->refs;++closed;dma_fence_put(&obj);}
static void dpu_save_fence_info(int fd,struct dma_fence *f,struct dpu_fence_info *i) {
    (void)i;assert(fd>=3 && f==&obj && f->refs==1 && file.refs==1);++logged;
}
''' + "\n".join(extract(source,s) for s in (
        "static int decon_get_valid_fd(",
        "void decon_cancel_release_fences(",
        "int decon_reserve_release_fences(",
        "int decon_create_fence(")) + r'''
int main(int argc,char **argv) {
    assert(argc==5);
    mode=atoi(argv[1]);low_count=atoi(argv[2]);
    fail_after=atoi(argv[3]);err_code=atoi(argv[4]);
    assert(low_count>=0 && low_count<=3);
    struct decon_device dev={.dt={3}};
    struct sync_file *out=NULL;
    if(mode==4) {
        struct decon_win_config_data w={0};
        for(int i=0;i<3;i++){w.config[i].state=2;w.config[i].rel_fence=29;}
        int rc=decon_reserve_release_fences(&dev,&w);
        assert(rc==err_code);
        for(int i=0;i<3;i++)assert(w.config[i].rel_fence==-1);
        assert(!file.refs && !obj.refs && !logged);
    } else {
        int rc=decon_create_fence(&dev,&out);
        if(mode==1 || mode==2) {
            assert(rc==-ENOMEM && !out && !calls && !logged && !closed);
        } else if(fail_after>=0) {
            assert(rc==err_code && !out && !logged && closed==1);
        } else {
            assert(rc==7 && out==&sync && logged==1 && obj.refs==1 && file.refs==1);
            assert(puts_count==low_count && state[rc]==1);
            put_unused_fd(rc);fput(out->file);
        }
    }
    assert(!obj.refs && !file.refs);
    for(int i=0;i<32;i++)assert(!state[i]);
    puts("DECON_RETIRE_GUARD_CASE_PASS");
    return 0;
}
'''

def compile_fixture(source, unit, exe):
    unit.write_text(harness(source))
    subprocess.run(["cc","-std=c11","-Wall","-Wextra","-Werror",str(unit),"-o",str(exe)],
                   check=True,timeout=30)


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
    unit=a.scratch/"retire.c"
    exe=a.scratch/"retire"
    compile_fixture(target.read_text(), unit, exe)
    cases=[(1,0,-1,0),(2,0,-1,0)]
    cases.extend((0,n,-1,0) for n in range(4))
    cases.extend((0,3,n,err) for n in range(4) for err in (-24,-12))
    cases.extend((4,0,n,err) for n in range(3) for err in (-24,-12))
    for args in cases:
        run=subprocess.run([str(exe.resolve()),*map(str,args)],capture_output=True,text=True,timeout=5)
        if run.returncode!=0 or run.stdout.strip()!="DECON_RETIRE_GUARD_CASE_PASS":
            raise ValueError("Unexpected retire fixture "+str(args)+": "+run.stderr)
    report={"status":"DECON_RETIRE_FD_SYNTHETIC_ONLY","source_sha":a.source_sha,
            "kernel_sha":BASE,"source_blob":PIN,"cases":len(cases),
            "errno_preservation_tested":True,"low_fd_rollback_tested":True,
            "retire_reference_model_tested":True,"kernel_runtime_verified":False,
            "hardware_tested":False,"safe_to_flash":False}
    (a.scratch/"retire-evidence.json").write_text(json.dumps(report,sort_keys=True)+"\n")
    print(json.dumps(report,sort_keys=True))

if __name__=="__main__":
    main()
