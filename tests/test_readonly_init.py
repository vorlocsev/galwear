"""Offline checks for the non-writing AArch64 PID1 smoke init.

These source-level guards constrain the experimental default. They do not
prove runtime safety on an actual SM-R800 or authenticate boot firmware.
"""
from __future__ import annotations

from pathlib import Path
import re
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src/initramfs/init-readonly.c"
BUILD = ROOT / "build/r800_initramfs_compile_smoke.sh"
REPEAT = ROOT / ".github/workflows/r800-init-repeatability.yml"


class ReadonlyInitTests(unittest.TestCase):
    def setUp(self):
        self.src = SRC.read_text(encoding="utf-8")

    def test_only_console_write_and_nanosleep_syscalls(self):
        # The two hard-coded AArch64 x8 syscall numbers. No open/mount/ioctl.
        numbers = [int(x) for x in re.findall(
            r'register\s+s64\s+x8\s+asm\("x8"\)\s*=\s*(\d+)\s*;', self.src)]
        self.assertEqual(numbers, [64, 101])
        self.assertEqual(self.src.count('asm volatile("svc #0"'), 2)

    def test_no_e_mmc_or_factory_partition_paths(self):
        for token in ("mmcblk", "/data/", "/dev/block/", "CSA", "EFS", "CM.bin",
                      "r800dev/start.sh", "sysrq", "/proc/cmdline"):
            with self.subTest(token=token):
                self.assertNotIn(token, self.src)

    def test_no_persistent_or_display_syscalls(self):
        for token in ("openat(", "mount(", "umount", "ioctl(", "mmap(", "execve(",
                      "reboot(", "sync(", "fb0", "FBIO", "i2c", "spi"):
            with self.subTest(token=token):
                self.assertNotIn(token, self.src)

    def test_stdout_only_no_device_file_opening(self):
        self.assertIn('register s64 x0 asm("x0") = 1;', self.src)
        self.assertNotIn('open("/dev/', self.src)
        self.assertIn("no eMMC mount, no Wear OS handover", self.src)

    def test_sleep_forever_without_busy_poll(self):
        self.assertIn("for (;;)", self.src)
        self.assertIn("(void)idle_sleep(&interval);", self.src)
        self.assertIn("const struct tiny_timespec interval = {5, 0};", self.src)

    def test_no_rw_legacy_init_in_compile_recipe(self):
        script = BUILD.read_text(encoding="utf-8")
        self.assertIn('"$REPO/src/initramfs/init-readonly.c"', script)
        self.assertNotIn('"$REPO/src/initramfs/init.c"', script)
        self.assertIn("--target=aarch64-linux-gnu", script)
        self.assertIn("-nostdlib -static", script)
        self.assertIn("-Wl,--build-id=none", script)

    def test_compile_recipe_shell_syntax(self):
        check = subprocess.run(["sh", "-n", str(BUILD)],
                               text=True, capture_output=True, timeout=5)
        self.assertEqual(check.returncode, 0, check.stderr)

    def test_two_runner_hashes_safe_source(self):
        workflow = REPEAT.read_text(encoding="utf-8")
        self.assertIn('"src/initramfs/init-readonly.c"', workflow)
        self.assertIn('read_only_init', workflow)
        self.assertIn('replica: [a, b]', workflow)
        self.assertIn('compare-two-runners:', workflow)

    def test_readonly_smoke_is_explicitly_nonrelease(self):
        self.assertIn("NON-RELEASE", self.src)
        self.assertIn("NOT a functional Wear OS", self.src)
        self.assertIn("safe_to_flash", REPEAT.read_text())

    def test_old_rw_init_still_separate_from_smoke(self):
        previous = (ROOT / "src/initramfs/init.c").read_text()
        self.assertIn("/dev/mmcblk0p17", previous)
        self.assertNotEqual(SRC, ROOT / "src/initramfs/init.c")

    def test_no_device_transport_in_new_init(self):
        for t in ("socket(", "connect(", "sendto(", "adb", "odin", "JTAG"):
            with self.subTest(token=t):
                self.assertNotIn(t, self.src)


if __name__ == "__main__":
    unittest.main()
