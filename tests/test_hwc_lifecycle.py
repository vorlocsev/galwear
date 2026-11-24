"""Host regression fixture for HWC framebuffer teardown and lifecycle guards."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class HwcLifecycleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = (ROOT / "src/hal/hwcomposer_r800.c").read_text()

    def test_framebuffer_close_is_idempotent(self):
        s = self.source
        actual = s[s.index("static void fb_close("):s.index("static int fb_open(")]
        harness = r'''
#include <assert.h>
#include <stddef.h>
struct r800_hwc {
    void *fb_mem;
    struct {size_t smem_len;} fix;
    int fb_fd;
};
static int unmaps, closes;
static int munmap(void *ptr, size_t size) {
    assert(ptr && size==4096);
    assert(!closes);
    unmaps++;
    return 0;
}
static int close(int fd) {
    assert(fd==7);
    closes++;
    return 0;
}
''' + actual + r'''
int main(void) {
    struct r800_hwc h={.fb_mem=(void *)1,.fix={4096},.fb_fd=7};
    fb_close(&h);
    assert(!h.fb_mem && h.fb_fd==-1);
    assert(unmaps==1 && closes==1);
    fb_close(&h);
    assert(unmaps==1 && closes==1);
    return 0;
}
'''
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "fb.c"
            exe = Path(tmp) / "fb"
            src.write_text(harness)
            subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                            str(src), "-o", str(exe)], check=True, timeout=15)
            subprocess.run([str(exe)], check=True, timeout=5)

    def test_framebuffer_open_unwinds_failures(self):
        s = self.source.split("static int fb_open(", 1)[1].split("static void fb_fill(", 1)[0]
        self.assertEqual(s.count("fb_close(h);"), 3)

    def test_workers_stopped_before_resources_released(self):
        s = self.source.split("static int r800_close(", 1)[1].split("static int r800_open(", 1)[0]
        self.assertLess(s.index("stop_workers(h);"), s.index("pthread_join("))
        self.assertLess(s.index("pthread_join(h->idle_thread"), s.index("fb_close(h);"))
        self.assertLess(s.index("fb_close(h);"), s.index("free(h);"))
        self.assertIn("return -EDEADLK;", s)

    def test_both_workers_observe_stop_flag(self):
        for start, end in (("static void *vsync_loop(", "static int r800_event_control("),
                           ("static void *doze_idle_loop(", "static int r800_set_power_mode(")):
            s = self.source.split(start, 1)[1].split(end, 1)[0]
            self.assertIn("while (!atomic_load(&h->stopping)", s)
            self.assertIn("if (atomic_load(&h->stopping))", s)

    def test_second_thread_failure_joins_first(self):
        s = self.source.split("static int r800_open(", 1)[1]
        self.assertIn("r = pthread_create(&h->idle_thread", s)
        self.assertIn("stop_workers(h);\n\t\tpthread_join(h->vsync_thread, NULL);", s)
        self.assertIn("fail_resources:\n\tfb_close(h);", s)

    def test_no_incomplete_device_published(self):
        s = self.source.split("static int r800_open(", 1)[1]
        self.assertLess(s.index("r = fb_open(h);"), s.index("*device = &h->base.common;"))
        self.assertIn("refusing incomplete HWC open", s)
        self.assertIn("!h->gralloc->lock || !h->gralloc->unlock", s)


if __name__ == "__main__":
    unittest.main()
