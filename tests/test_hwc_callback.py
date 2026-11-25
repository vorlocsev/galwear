"""Test production callback handoff with host pthreads, not a device."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src/hal/hwcomposer_r800.c"


class HwcCallbackTests(unittest.TestCase):
    def test_replace_waits_for_inflight_callback(self):
        source = SOURCE.read_text()
        helpers = source[source.index("static const hwc_procs_t *r800_callback_acquire("):
                         source.index("static void *vsync_loop(")]
        harness = r"""
#include <assert.h>
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <sched.h>
typedef struct hwc_procs {
    void (*vsync)(const struct hwc_procs *, int, int64_t);
} hwc_procs_t;
struct r800_hwc {
    pthread_mutex_t lock;
    pthread_cond_t cond;
    pthread_t vsync_thread;
    int vsync_stop, vsync_started, vsync_enabled;
    unsigned long vsync_epoch;
    unsigned int callback_active, callback_waiters;
    const hwc_procs_t *procs;
};
""" + helpers + r"""
static void noop(const hwc_procs_t *p, int d, int64_t t)
{ (void)p; (void)d; (void)t; }
static const hwc_procs_t first = {noop}, second = {noop};
static void *replace(void *arg)
{
    r800_callback_replace(arg, &second);
    return NULL;
}
int main(void)
{
    for (int n = 0; n < 100; ++n) {
        struct r800_hwc h = {0};
        pthread_t t;
        assert(!pthread_mutex_init(&h.lock, NULL));
        assert(!pthread_cond_init(&h.cond, NULL));
        h.vsync_enabled = 1;
        r800_callback_replace(&h, &first);
        assert(h.vsync_epoch == 1);
        assert(r800_callback_acquire(&h, 0) == NULL);
        assert(r800_callback_acquire(&h, 1) == &first);
        assert(!pthread_create(&t, NULL, replace, &h));
        for (;;) {
            pthread_mutex_lock(&h.lock);
            unsigned int waiting = h.callback_waiters;
            assert(h.procs == &first);
            pthread_mutex_unlock(&h.lock);
            if (waiting) break;
            sched_yield();
        }
        assert(r800_callback_acquire(&h, 1) == NULL);
        r800_callback_release(&h);
        assert(!pthread_join(t, NULL));
        assert(h.procs == &second && h.vsync_epoch == 2);
        assert(r800_callback_acquire(&h, 1) == NULL);
        assert(r800_callback_acquire(&h, 2) == &second);
        r800_callback_release(&h);
        r800_callback_replace(&h, NULL);
        assert(r800_callback_acquire(&h, 3) == NULL);
        assert(!h.callback_active && !h.callback_waiters);
        h.vsync_stop = 1;
        r800_callback_replace(&h, &first);
        assert(h.procs == NULL);
        assert(!pthread_cond_destroy(&h.cond));
        assert(!pthread_mutex_destroy(&h.lock));
    }
    return 0;
}
"""
        with tempfile.TemporaryDirectory() as tmp:
            c = Path(tmp) / "callback.c"
            exe = Path(tmp) / "callback"
            c.write_text(harness)
            result = subprocess.run(["cc", "-std=c99", "-Wall", "-Wextra",
                                     "-Werror", "-pthread", str(c), "-o", str(exe)],
                                    capture_output=True, text=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr)
            subprocess.run([str(exe)], check=True, timeout=10)

    def test_dispatch_pins_registration_and_releases_it(self):
        source = SOURCE.read_text()
        loop = source[source.index("static void *vsync_loop("):
                      source.index("static int r800_set_vsync_irq_locked(")]
        self.assertLess(loop.index("r800_callback_acquire(h, epoch)"),
                        loop.index("procs->vsync(procs, 0, ts)"))
        self.assertLess(loop.index("procs->vsync(procs, 0, ts)"),
                        loop.index("r800_callback_release(h)"))
        register = source[source.index("static void r800_register_procs("):
                          source.index("static int r800_get_display_configs(")]
        self.assertIn("r800_callback_replace(h, procs);", register)


if __name__ == "__main__":
    unittest.main()
