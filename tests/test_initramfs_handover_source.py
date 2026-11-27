"""Static handover guards; never run the device PID1 on the host."""
from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]
INIT = ROOT / "src/initramfs/init.c"
BUILD = ROOT / "src/initramfs/build.sh"


class HandoverSourceTests(unittest.TestCase):
    def setUp(self):
        self.source = INIT.read_text()
        self.recipe = BUILD.read_text()

    def test_framebuffer_ioctl_guard(self):
        start = self.source.index("if (vr == 0 && fr == 0)")
        end = self.source.index('klog("framebuffer metadata unavailable', start)
        for marker in ("xres = *(unsigned int *)", "smem = *(unsigned int *)",
                       "sc6(222, 0, smem"):
            self.assertIn(marker, self.source[start:end])

    def test_framebuffer_geometry_guard(self):
        start = self.source.index("if (bpp == 32 && xres == 360")
        end = self.source.index("sc6(222, 0, smem", start)
        for marker in ("yres == 360", "line >= (u64)xres * 4",
                       "(line % 4) == 0",
                       "(u64)(yres - 1) * line + (u64)xres * 4 <= smem",
                       "smem <= 64U * 1024U * 1024U"):
            self.assertIn(marker, self.source[start:end])

    def test_failed_mapping_not_used(self):
        self.assertIn("if (m > 0) pix = (unsigned int *)m;", self.source)

    def test_mount_gates_splash_and_exec(self):
        self.assertIn('s64 sf = data_mount == 0 ? openat("/data/r800dev/splash.raw", 0) : -1;', self.source)
        begin = self.source.index("if (data_mount == 0) {")
        end = self.source.index('klog("hand-over failed', begin)
        self.assertIn('sc(221, (s64)"/data/r800dev/bin/busybox"', self.source[begin:end])

    def test_build_only_no_host_paths(self):
        subprocess.run(["sh", "-n", str(BUILD)], check=True)
        for forbidden in ("/mnt/d/", "~/kernel", "kbuild-native.sh"):
            self.assertNotIn(forbidden, self.recipe)
        self.assertIn("-Wl,--build-id=none", self.recipe)
        self.assertIn("os.utime", self.recipe)
        self.assertIn("NON-RELEASE", self.recipe)


if __name__ == "__main__":
    unittest.main()
