#!/usr/bin/env python3
"""Pinned DECON command-mode buffer ownership on rejected acquire wait."""
import argparse
import json
from pathlib import Path
import re
import subprocess
from r800_kbase_abi_check import BASE, git_blob
from r800_decon_retire_guard import extract

SOURCE = "drivers/video/fbdev/exynos/dpu30/decon_core.c"
PIN = "fcb2ca536ba7288ec656973e04bd17d9de2cec20"

def failure_branch(source):
    fn = extract(source, "static void decon_update_regs(")
    start = fn.index("if (err <= 0) {", fn.index("err = decon_wait_fence("))
    end = fn.index("goto fence_err;", start)+len("goto fence_err;")
    return fn[start:end]+"\n}"


def harness(source):
    functions = "\n".join(extract(source, "static void "+name+"(") for name in (
        "decon_acquire_old_bufs", "decon_release_old_bufs",
        "decon_save_cur_buf_info", "decon_acquire_cur_bufs"))
    return r'''
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define MAX_PLANE_CNT 3
#define MAX_DECON_WIN 3
#define DECON_OUT_DSI 0
#define DECON_OUT_WB 2
#define DECON_MIPI_COMMAND_MODE 2
#define DECON_VIDEO_MODE 0
#define VSYNC_TIMEOUT_MSEC 100
#define v4l2_subdev_call(...) ((void)0)
struct decon_dma_buf_data {int id;};
struct decon_win {
    int plane_cnt;
    struct decon_dma_buf_data dma_buf_data[3];
};
struct decon_reg_data {
    int plane_cnt[4];
    struct decon_dma_buf_data dma_buf_data[4][3];
};
struct lcd_info {int mode;};
struct dsim_device {struct {int reserved;} fb_handover;};
struct decon_device {
    struct {int max_win,out_type,psr_mode;} dt;
    struct decon_win *win[3];
    struct lcd_info *lcd_info;
    void *out_sd[1];
};
static unsigned decon_trivial;
static int released[64], live[64], vsyncs;
static struct dsim_device dsim;
static struct dsim_device *v4l2_get_subdevdata(void *p) {(void)p;return &dsim;}
static void decon_free_dma_buf(struct decon_device *d,struct decon_dma_buf_data *buf) {
    (void)d;int id=buf->id;assert(id>0 && id<64 && live[id] && !released[id]);
    live[id]=0;++released[id];buf->id=0;
}
static void decon_wait_for_vsync(struct decon_device *d,int timeout) {
    (void)d;assert(timeout==VSYNC_TIMEOUT_MSEC);++vsyncs;
}
''' + functions + r'''
static void reject(struct decon_device *decon,struct decon_reg_data *regs) {
    struct decon_dma_buf_data old_dma_bufs[3][3];
    int old_plane_cnt[3];
    int err=-5;
    bool winup_rollback=false;
    decon_acquire_old_bufs(decon,regs,old_dma_bufs,old_plane_cnt);
''' + failure_branch(source) + r'''
    assert(0);
fence_err:
    assert(winup_rollback);
    decon_release_old_bufs(decon,regs,old_dma_bufs,old_plane_cnt);
}
static void fill(struct decon_reg_data *r,int base,int variant) {
    for(int i=0;i<3;i++) {
        r->plane_cnt[i]=variant==0?i+1:variant==1?3-i:0;
        for(int j=0;j<r->plane_cnt[i];j++) {
            int id=base+i*3+j;
            r->dma_buf_data[i][j].id=id;live[id]=1;
        }
    }
}
static int valid_owner(struct decon_device *d,struct decon_reg_data *r) {
    for(int i=0;i<3;i++) {
        if(d->win[i]->plane_cnt!=r->plane_cnt[i])return 0;
        for(int j=0;j<r->plane_cnt[i];j++) {
            int id=r->dma_buf_data[i][j].id;
            if(d->win[i]->dma_buf_data[j].id!=id || !live[id])return 0;
        }
    }
    return 1;
}
static void assert_released(struct decon_reg_data *r) {
    for(int i=0;i<3;i++)for(int j=0;j<r->plane_cnt[i];j++)
        assert(released[r->dma_buf_data[i][j].id]==1);
}
int main(int argc,char **argv) {
    assert(argc==5);
    int command=atoi(argv[1]), expected_preserve=atoi(argv[2]),variant=atoi(argv[3]);
    decon_trivial=atoi(argv[4]);
    struct lcd_info lcd={command?DECON_MIPI_COMMAND_MODE:DECON_VIDEO_MODE};
    struct decon_win wins[3]={0};
    struct decon_device d={.dt={3,DECON_OUT_DSI,lcd.mode},
                           .win={&wins[0],&wins[1],&wins[2]},.lcd_info=&lcd};
    struct decon_reg_data old={0},bad={0},next={0};
    fill(&old,1,0);fill(&bad,12,variant);fill(&next,24,1);
    decon_save_cur_buf_info(&d,&old);
    reject(&d,&bad);
    assert(vsyncs==1);
    if(expected_preserve && !valid_owner(&d,&old))return 42;
    struct decon_reg_data *kept=expected_preserve?&old:&bad;
    assert(valid_owner(&d,kept));
    assert_released(expected_preserve?&bad:&old);
    /* Model the ownership transfer on a later accepted frame. */
    struct decon_dma_buf_data previous[3][3];
    int counts[3];
    decon_acquire_old_bufs(&d,&next,previous,counts);
    decon_save_cur_buf_info(&d,&next);
    decon_release_old_bufs(&d,&next,previous,counts);
    assert_released(kept);
    assert(valid_owner(&d,&next));
    puts("DECON_BUFFER_GUARD_CASE_PASS");
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
    cases=[(1,1,variant,debug) for variant in (0,1,2) for debug in (0,1)]
    cases.extend((0,debug,variant,debug) for variant in (0,1) for debug in (0,1))
    for name,source,rows in (("original",raw.decode(),[(1,1,1,0)]),
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
                    raise ValueError("Original command-mode ownership loss not reproduced")
            elif result.returncode or result.stdout.strip()!="DECON_BUFFER_GUARD_CASE_PASS":
                raise ValueError("Unexpected buffer ownership result "+str(args)+": "+result.stderr)
    report={"status":"DECON_COMMAND_BUFFER_OWNERSHIP_SYNTHETIC_ONLY",
            "source_sha":a.source_sha,"kernel_sha":BASE,"source_blob":PIN,"cases":len(cases),
            "original_ownership_loss_reproduced":True,"video_policy_unchanged":True,
            "writeback_policy_unchanged":True,"real_dma_buf_lifetime_verified":False,
            "display_output_verified":False,"safe_to_flash":False}
    (a.scratch/"buffer-evidence.json").write_text(json.dumps(report,sort_keys=True)+"\n")
    print(json.dumps(report,sort_keys=True))

if __name__=="__main__":
    main()
