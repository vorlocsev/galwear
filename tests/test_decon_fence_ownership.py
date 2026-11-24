"""Compile the actual added kernel release-fence function with fault injection."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
PATCH = ROOT / "src/kernel/r800-wearos.patch"
HWC = ROOT / "src/hal/hwcomposer_r800.c"


class FenceOwnershipTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        p = PATCH.read_text()
        section = p.split("diff --git a/drivers/video/fbdev/exynos/dpu30/fence.c ", 1)[1]
        section = section.split("diff --git ", 1)[0]
        new = "\n".join(line[1:] for line in section.splitlines()
                        if line.startswith(("+", " ")) and not line.startswith("+++"))
        start = new.index("int decon_create_release_fences(")
        stop = new.index("\n}", start) + 2
        actual = new[start:stop]
        harness = r'''
#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#define DECON_WIN_STATE_BUFFER 2
#define DPU_F_EVT_LOG(...) ((void)0)
struct dma_fence {int dummy;};
struct file {int refs;};
struct sync_file {struct file *file; struct dma_fence *fence;};
struct dpu_fence_info {int dummy;};
struct decon_device {struct {int max_win;} dt;};
struct decon_win_config_data {struct {int state,rel_fence;} config[4];};
static int failure, calls, installed, released;
static int state[64];
static int decon_get_valid_fd(void) {
    int i=calls++;
    if(i==failure) return -EMFILE;
    state[10+i]=1; return 10+i;
}
static struct file *get_file(struct file *f) {f->refs++;return f;}
static void fd_install(int fd,struct file *f) {
    assert(state[fd]==1 && f->refs>1);
    state[fd]=2;installed++;
}
static void put_unused_fd(int fd) {
    assert(state[fd]==1);
    state[fd]=0;released++;
}
static void dpu_save_fence_info(int fd,struct dma_fence *f,struct dpu_fence_info *i) {
    (void)fd;(void)f;(void)i;
}
''' + actual + r'''
int main(int argc,char **argv) {
    assert(argc==3);
    failure=atoi(argv[1]);
    int mask=atoi(argv[2]), active=0;
    struct file file={.refs=1};
    struct dma_fence fence={0};
    struct sync_file sync={.file=&file,.fence=&fence};
    struct decon_device dev={.dt={.max_win=3}};
    struct decon_win_config_data data={0};
    for(int i=0;i<3;i++) {
        data.config[i].state=(mask&(1<<i))?2:0;
        data.config[i].rel_fence=42;
        active+=data.config[i].state==2;
    }
    int result=decon_create_release_fences(&dev,&data,&sync);
    if(failure>=0 && failure<active) {
        assert(result==-EMFILE && installed==0 && released==failure && file.refs==1);
        for(int i=0;i<3;i++) assert(data.config[i].rel_fence==-1);
    } else {
        assert(result==0 && installed==active && released==0 && file.refs==1+active);
        for(int i=0;i<3;i++)
            assert((data.config[i].rel_fence>=0)==!!(mask&(1<<i)));
    }
    return 0;
}
'''
        cls.temp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temp.cleanup)
        src = Path(cls.temp.name) / "release.c"
        cls.exe = Path(cls.temp.name) / "release"
        src.write_text(harness)
        subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                        str(src), "-o", str(cls.exe)], check=True, timeout=15)

    def run_fixture(self, failure, mask):
        subprocess.run([str(self.exe), str(failure), str(mask)], check=True, timeout=5)

    def test_all_three_reserved_before_install(self):
        self.run_fixture(-1, 7)

    def test_each_reservation_failure(self):
        for i in range(3):
            with self.subTest(i=i):
                self.run_fixture(i, 7)

    def test_sparse_windows(self):
        for mask in (0, 1, 2, 4, 5, 6):
            with self.subTest(mask=mask):
                self.run_fixture(-1, mask)

    def test_sparse_windows_rollback(self):
        self.run_fixture(1, 5)

    def test_release_fd_transferred(self):
        source = HWC.read_text()
        self.assertIn("l->releaseFenceFd = d.config[w].rel_fence;", source)
        self.assertIn("d.config[w].rel_fence = -1;", source)

    def test_overlay_explicit_opt_in(self):
        self.assertIn('return !strcmp(v, "1");', HWC.read_text())

    def test_patch_format(self):
        subprocess.run(["git", "apply", "--numstat", str(PATCH)], cwd=ROOT,
                       check=True, capture_output=True, timeout=15)


if __name__ == "__main__":
    unittest.main()
