"""Compile the actual patched DECON transaction with host-only fault injection."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


def extract(patch, name, signature):
    section = patch.split("diff --git a/drivers/video/fbdev/exynos/dpu30/"+name+" ",1)[1]
    section = section.split("diff --git ",1)[0]
    source = "\n".join(line[1:] for line in section.splitlines()
                       if line.startswith(("+"," ")) and not line.startswith("+++"))
    start = source.index(signature)
    return source[start:source.index("\n}",start)+2]


PRELUDE = r'''
#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#define MAX_DECON_WIN 3
#define DECON_WIN_STATE_BUFFER 2
#define DECON_STATE_TUI 4
#define DECON_MIPI_COMMAND_MODE 1
#define GFP_KERNEL 0
#define __user
#define IS_ENABLED(x) 0
#define IS_DECON_OFF_STATE(d) ((d)->state == 1)
#define decon_dbg(...) ((void)0)
#define decon_err(...) ((void)0)
#define DPU_F_EVT_LOG(...) ((void)0)
#define decon_systrace(...) ((void)0)
struct decon_rect {int x;};
struct dma_fence {int refs;};
struct file {int refs;};
struct sync_file {struct file *file; struct dma_fence *fence;};
struct dpu_fence_info {int dummy;};
struct decon_win_config_data {
    int retire_fence;
    struct {int state,rel_fence;} config[4];
};
struct decon_reg_data {
    int plane_cnt[3],list;
    struct decon_rect up_region;
    struct dma_fence *retire_fence;
};
struct lcd {int mode;};
struct decon_device {
    int lock,state,id;
    struct {int max_win;} dt;
    struct lcd *lcd_info;
    struct {struct decon_rect back_up_region,prev_up_region;} win_up;
    struct {int lock,list,remaining_frame,worker,work;} up;
};
static int mode, calls, reservations, installs, releases, copy_calls, frees, queued;
static int signals, fputs, worker_refs, hiber, active, locked;
static int fd_state[64];
static struct file file;
static struct dma_fence fence;
static struct sync_file sync={&file,&fence};
static struct decon_reg_data *pending;
static void mutex_lock(int *p) {assert(!*p);*p=1;++locked;}
static void mutex_unlock(int *p) {assert(*p);*p=0;--locked;}
static int decon_get_valid_fd(void) {
    int i=calls++;
    if ((mode==2 && i==0) || (mode>=4 && mode<=6 && i==mode-3)) return -EMFILE;
    int fd=10+i; assert(!fd_state[fd]);fd_state[fd]=1;++reservations;return fd;
}
static struct file *get_file(struct file *f) {assert(f==&file && f->refs>0);++f->refs;return f;}
static void fd_install(int fd,struct file *f) {
    assert(copy_calls==1 && f==&file && f->refs>0 && fd_state[fd]==1);
    fd_state[fd]=2;++installs;
}
static void put_unused_fd(int fd) {assert(fd_state[fd]==1);fd_state[fd]=0;++releases;}
static void fput(struct file *f) {assert(f==&file && f->refs>0);--f->refs;++fputs;}
static struct dma_fence *dma_fence_get(struct dma_fence *f) {
    assert(f==&fence && f->refs>0);++f->refs;++worker_refs;return f;
}
static void dpu_save_fence_info(int fd,struct dma_fence *f,struct dpu_fence_info *i) {
    (void)fd;(void)f;(void)i;
}
static int decon_create_fence(struct decon_device *d,struct sync_file **out) {
    (void)d;int fd=decon_get_valid_fd();
    if(fd<0){*out=NULL;return fd;}
    file.refs=1;fence.refs=1;*out=&sync;return fd;
}
static void decon_signal_fence(struct decon_device *d,struct dma_fence *f) {
    (void)d;assert(f==&fence);++signals;
}
static void *kzalloc(size_t n,int flags) {(void)flags;return mode==1?NULL:calloc(1,n);}
static void kfree(void *p) {free(p);}
static int decon_get_active_win_count(struct decon_device *d,struct decon_win_config_data *w) {
    (void)d;(void)w;return active;
}
static void dpu_prepare_win_update_config(struct decon_device *d,struct decon_win_config_data *w,struct decon_reg_data *r) {
    (void)d;(void)w;r->up_region.x=99;
}
static int decon_prepare_win_config(struct decon_device *d,struct decon_win_config_data *w,struct decon_reg_data *r) {
    (void)d;(void)w;
    for(int i=0;i<active;i++)r->plane_cnt[i]=1;
    return mode==3?-EINVAL:0;
}
static void decon_free_unused_buf(struct decon_device *d,struct decon_reg_data *r,int i,int j) {
    (void)d;assert(j<r->plane_cnt[i]);++frees;
}
static int copy_to_user(struct decon_win_config_data *u,struct decon_win_config_data *w,size_t n) {
    assert(installs==0 && queued==0 && n==sizeof(*w));++copy_calls;
    if(mode==7) {memcpy(u,w,n/2);return 1;}
    memcpy(u,w,n);return 0;
}
static void decon_hiber_block(struct decon_device *d) {(void)d;++hiber;}
static void list_add_tail(int *item,int *list) {
    (void)list;pending=(struct decon_reg_data *)((char *)item-__builtin_offsetof(struct decon_reg_data,list));
}
static void atomic_inc(int *v) {++*v;}
static void dpu_update_freq_hop(struct decon_device *d) {(void)d;}
static void kthread_queue_work(int *worker,int *work) {(void)worker;(void)work;++queued;}
'''

MAIN = r'''
int main(int argc,char **argv) {
    assert(argc==4);
    mode=atoi(argv[1]);int off=atoi(argv[2]);active=atoi(argv[3]);
    struct lcd lcd={DECON_MIPI_COMMAND_MODE};
    struct decon_device dev={.state=off,.dt={3},.lcd_info=&lcd,.win_up={{5},{6}}};
    struct decon_win_config_data w={.retire_fence=42},user={0};
    for(int i=0;i<4;i++) {
        w.config[i].state=i<active?DECON_WIN_STATE_BUFFER:0;
        w.config[i].rel_fence=43+i;
    }
    int rc=decon_set_win_config(&dev,&w,&user);
    int expected=mode==1?-ENOMEM:mode==2?-EMFILE:mode==3?-EINVAL:
                 mode>=4 && mode<=6?-EMFILE:mode==7?-EFAULT:0;
    if(off && mode==1)expected=0;
    assert(rc==expected && !locked);
    if(rc) {
        assert(installs==0 && queued==0 && hiber==0 && worker_refs==0);
        assert(reservations==releases && file.refs==0);
        assert(dev.win_up.prev_up_region.x==6);
        assert(copy_calls==(mode==7));
        assert(frees==(!off && mode>=3 ? active:0));
    } else {
        assert(copy_calls==1 && releases==0);
        assert(user.config[3].rel_fence==-1);
        if(off) {
            assert(installs==1 && signals==1 && queued==0 && worker_refs==0);
        } else {
            assert(queued==1 && hiber==1 && dev.up.remaining_frame==1);
            assert(dev.win_up.prev_up_region.x==99 && dev.win_up.back_up_region.x==6);
            assert(installs==(active?active+1:0) && worker_refs==!!active);
            assert(pending && pending->retire_fence==(active?&fence:NULL));
            free(pending);
        }
        assert(file.refs==installs);
        for(int fd=0;fd<64;fd++)if(fd_state[fd]==2){fd_state[fd]=0;fput(&file);}
        assert(file.refs==0);
    }
    for(int fd=0;fd<64;fd++)assert(fd_state[fd]==0);
    return 0;
}
'''


class DeconTransactionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        patch=(ROOT/"src/kernel/r800-wearos.patch").read_text()
        source=PRELUDE+"\n".join(extract(patch,"fence.c",s) for s in (
            "void decon_cancel_release_fences(", "int decon_reserve_release_fences(",
            "void decon_install_release_fences("))
        source+=extract(patch,"decon_core.c","static int decon_set_win_config(")+MAIN
        cls.temp=tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temp.cleanup)
        unit=Path(cls.temp.name)/"transaction.c"
        cls.exe=Path(cls.temp.name)/"transaction"
        unit.write_text(source)
        subprocess.run(["cc","-std=c11","-Wall","-Wextra","-Werror",str(unit),"-o",str(cls.exe)],
                       check=True,timeout=20)

    def run_case(self,mode,off,active):
        subprocess.run([str(self.exe),str(mode),str(off),str(active)],check=True,timeout=5)

    def test_active_success(self):
        for active in (0,1,2,3):
            with self.subTest(active=active): self.run_case(0,0,active)

    def test_active_all_failure_stages(self):
        for mode in range(1,8):
            with self.subTest(mode=mode): self.run_case(mode,0,3)

    def test_off_state_success_and_failure(self):
        for mode in (0,1,2,7):
            with self.subTest(mode=mode): self.run_case(mode,1,3)

    def test_no_active_copyout_failure(self):
        self.run_case(7,0,0)
