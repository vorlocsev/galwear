"""Host-only acquire-fence tests, using pipes as poll readiness fixtures."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class HwcFenceSafetyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = (ROOT / "src/hal/hwcomposer_r800.c").read_text()
        s = cls.source
        helper = s[s.index("static int wait_fence("):s.index("/* ---- framebuffer ---- */")]
        harness = r'''
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <unistd.h>
#include <stdlib.h>
''' + helper + r'''
int main(int argc, char **argv) {
    assert(argc == 2);
    int mode=atoi(argv[1]), fds[2];
    if (mode==0) { assert(wait_fence(-1)==0); assert(wait_fence(-2)==-EINVAL); return 0; }
    assert(pipe(fds)==0);
    if (mode==1) assert(write(fds[1],"x",1)==1);
    if (mode==3) { close(fds[1]); fds[1]=-1; }
    if (mode==4) close(fds[0]);
    int rc=wait_fence(fds[0]);
    assert(rc==(mode==1?0:mode==2?-ETIMEDOUT:-EIO));
    assert(fcntl(fds[0],F_GETFD)==-1 && errno==EBADF);
    if (fds[1]>=0) close(fds[1]);
    return 0;
}
'''
        cls.tmp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.tmp.cleanup)
        src = Path(cls.tmp.name) / "fence.c"
        cls.exe = Path(cls.tmp.name) / "fence"
        src.write_text(harness)
        subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                        str(src), "-o", str(cls.exe)], check=True, timeout=15)

    def run_fixture(self, mode):
        subprocess.run([str(self.exe), str(mode)], check=True, timeout=5)

    def test_no_fence(self):
        self.run_fixture(0)

    def test_ready(self):
        self.run_fixture(1)

    def test_timeout(self):
        self.run_fixture(2)

    def test_hangup(self):
        self.run_fixture(3)

    def test_invalid_fd(self):
        self.run_fixture(4)

    def test_no_unfenced_fallback(self):
        self.assertNotIn("fb_present(h, fallback", self.source)
        self.assertIn("int ready = wait_fence(l->acquireFenceFd);", self.source)
        self.assertIn("else if (!h->blanked && fb_present(h, l->handle, 1) == 0)", self.source)

    def test_framebuffer_bounds_and_pan_failure(self):
        self.assertIn("h->var.bits_per_pixel != 32", self.source)
        self.assertIn("(uint64_t)h->var.yres * h->fix.line_length > h->fix.smem_len", self.source)
        self.assertIn("FBIOPAN_DISPLAY, &next", self.source)

    def test_doze_timestamp_only_on_present(self):
        self.assertIn("if (presented)\n\t\tdoze_presented(h);", self.source)


if __name__ == "__main__":
    unittest.main()
