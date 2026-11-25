"""Host-only VSync IRQ tests, extracting production C."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class VsyncIrqTests(unittest.TestCase):
    def test_irq_acknowledgement(self):
        s = (ROOT / "src/hal/hwcomposer_r800.c").read_text()
        helper = s[s.index("static int r800_set_vsync_irq_locked("):
                   s.index("static int r800_event_control(")]
        code = r"""
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#define R800_S3CFB_SET_VSYNC_INT 206
struct r800_hwc { int vsync_irq_known, vsync_irq_enabled, fb_fd; };
static int calls, fail;
static unsigned last;
static int ioctl(int fd, int req, uint32_t *on) {
    assert(fd == 7 && req == 206);
    calls++;
    last = *on;
    if (fail) {
        errno = fail;
        fail = 0;
        return -1;
    }
    return 0;
}
""" + helper + r"""
int main(void) {
    struct r800_hwc h = {0, 0, -1};
    assert(r800_set_vsync_irq_locked(&h, 1) == -ENODEV);
    assert(calls == 0 && !h.vsync_irq_known);
    h.fb_fd = 7;
    fail = EIO;
    assert(r800_set_vsync_irq_locked(&h, 1) == -EIO);
    assert(calls == 1 && !h.vsync_irq_known);
    fail = EINTR;
    assert(!r800_set_vsync_irq_locked(&h, 1));
    assert(calls == 3 && h.vsync_irq_known && h.vsync_irq_enabled);
    assert(!r800_set_vsync_irq_locked(&h, 1) && calls == 3);
    fail = EACCES;
    assert(r800_set_vsync_irq_locked(&h, 0) == -EACCES);
    assert(!h.vsync_irq_known && last == 0);
    assert(!r800_set_vsync_irq_locked(&h, 0));
    assert(calls == 5 && h.vsync_irq_known && !h.vsync_irq_enabled);
    assert(!r800_set_vsync_irq_locked(&h, 0) && calls == 5);
    return 0;
}
"""
        with tempfile.TemporaryDirectory() as tmp:
            c = Path(tmp) / "irq.c"
            exe = Path(tmp) / "irq"
            c.write_text(code)
            subprocess.run(["cc", "-std=c99", "-Wall", "-Wextra", "-Werror",
                            str(c), "-o", str(exe)], check=True, timeout=15)
            subprocess.run([str(exe)], check=True, timeout=5)

    def test_kernel_accounting_lock(self):
        f = "drivers/video/fbdev/exynos/dpu30/decon_core.c"
        diff = (ROOT / "src/kernel/r800-wearos.patch").read_text().split(
            f"diff --git a/{f} b/{f}\n", 1)[1].split("\ndiff --git ", 1)[0]
        post = "\n".join(x[1:] for x in diff.splitlines()
                         if x.startswith((" ", "+")) and not x.startswith("+++"))
        fn = post.split("int decon_set_vsync_int(", 1)[1].split(
            "static unsigned int decon_map_ion_handle(", 1)[0]
        self.assertLess(fn.index("mutex_lock(&decon->vsync.lock)"),
                        fn.index("if (active != decon->vsync.active)"))
        self.assertLess(fn.index("WRITE_ONCE(decon->vsync.active, active)"),
                        fn.index("mutex_unlock(&decon->vsync.lock)"))
        self.assertIn("if (WARN_ON_ONCE(decon->vsync.irq_refcount <= 0))", post)


if __name__ == "__main__":
    unittest.main()
