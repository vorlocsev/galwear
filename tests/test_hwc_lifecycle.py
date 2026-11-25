"""Host-only HWC lifecycle regressions: exercise production stop logic."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src/hal/hwcomposer_r800.c"


class HwcLifecycleTests(unittest.TestCase):
    def test_worker_stop_with_real_pthreads(self):
        source = SOURCE.read_text()
        stop = source[source.index("static int r800_stop_workers("):
                      source.index("static void r800_release(")]
        irq = source[source.index("static int r800_set_vsync_irq_locked("):
                     source.index("static int r800_event_control(")]
        harness = r"""
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#define LOGW(...) ((void)0)
#define R800_S3CFB_SET_VSYNC_INT 0
struct r800_hwc {
    pthread_t vsync_thread, idle_thread;
    pthread_mutex_t lock, doze_lock;
    pthread_cond_t cond, doze_cond;
    int vsync_stop, idle_stop, vsync_started, idle_started;
    int vsync_enabled, fb_fd;
    int vsync_irq_known, vsync_irq_enabled;
    unsigned long vsync_epoch;
    void *procs;
};
""" + irq + stop + r"""
static void *vsync_worker(void *arg) {
    struct r800_hwc *h = arg;
    pthread_mutex_lock(&h->lock);
    while (!h->vsync_stop)
        pthread_cond_wait(&h->cond, &h->lock);
    pthread_mutex_unlock(&h->lock);
    return NULL;
}
static void *idle_worker(void *arg) {
    struct r800_hwc *h = arg;
    pthread_mutex_lock(&h->doze_lock);
    while (!h->idle_stop)
        pthread_cond_wait(&h->doze_cond, &h->doze_lock);
    pthread_mutex_unlock(&h->doze_lock);
    return NULL;
}
int main(void) {
    for (int n = 0; n < 100; ++n) {
        struct r800_hwc h = {0};
        h.fb_fd = -1;
        h.vsync_enabled = 1;
        h.procs = &h;
        assert(!pthread_mutex_init(&h.lock, NULL));
        assert(!pthread_mutex_init(&h.doze_lock, NULL));
        assert(!pthread_cond_init(&h.cond, NULL));
        assert(!pthread_cond_init(&h.doze_cond, NULL));
        if (n % 3 != 0) {
            assert(!pthread_create(&h.vsync_thread, NULL, vsync_worker, &h));
            h.vsync_started = 1;
        }
        if (n % 3 == 2) {
            assert(!pthread_create(&h.idle_thread, NULL, idle_worker, &h));
            h.idle_started = 1;
        }
        assert(!r800_stop_workers(&h));
        assert(h.vsync_stop && h.idle_stop);
        assert(!h.vsync_started && !h.idle_started);
        assert(!h.vsync_enabled && !h.procs);
        assert(h.vsync_epoch == 1);
        assert(!pthread_cond_destroy(&h.cond));
        assert(!pthread_cond_destroy(&h.doze_cond));
        assert(!pthread_mutex_destroy(&h.lock));
        assert(!pthread_mutex_destroy(&h.doze_lock));
    }
    return 0;
}
"""
        with tempfile.TemporaryDirectory() as tmp:
            c = Path(tmp) / "lifecycle.c"
            exe = Path(tmp) / "lifecycle"
            c.write_text(harness)
            result = subprocess.run(["cc", "-std=c99", "-Wall", "-Wextra",
                                     "-Werror", "-pthread", str(c), "-o", str(exe)],
                                    capture_output=True, text=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr)
            subprocess.run([str(exe)], check=True, timeout=10)

    def test_close_joins_before_release(self):
        source = SOURCE.read_text()
        close = source[source.index("static int r800_close("):
                       source.index("static int r800_open(")]
        self.assertLess(close.index("r800_stop_workers(h)"),
                        close.index("r800_release(h)"))
        self.assertIn("if (r)\n\t\treturn r;", close)

    def test_release_owns_resources(self):
        source = SOURCE.read_text()
        release = source[source.index("static void r800_release("):
                         source.index("static int r800_close(")]
        for action in ("munmap(", "close(h->fb_fd)", "dlclose(",
                       "pthread_cond_destroy(", "pthread_mutex_destroy(", "free(h)"):
            self.assertIn(action, release)

    def test_both_loops_observe_stop(self):
        source = SOURCE.read_text()
        for marker in ("while (!h->vsync_enabled && !h->vsync_stop)",
                       "if (h->vsync_stop)", "if (h->idle_stop)",
                       "while (!h->idle_stop &&"):
            self.assertIn(marker, source)

    def test_partial_open_never_publishes_device(self):
        source = SOURCE.read_text()
        start = source[source.index("static int r800_open("):]
        self.assertIn("*device = NULL;", start)
        self.assertIn("int stop = r800_stop_workers(h);", start)
        self.assertLess(start.index("h->idle_started = 1;"),
                        start.index("*device = &h->base.common;"))
        self.assertIn("fail_doze_lock:", start)


if __name__ == "__main__":
    unittest.main()
