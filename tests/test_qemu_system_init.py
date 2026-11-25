"""Synthetic tests for the generic ARM64 system boot gate."""
from pathlib import Path
import gzip
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "build"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import r800_qemu_system_init as a
from test_initramfs_recipe import fake_aarch64_elf

START = b"[    1.234] Run /init as init process\r\n"


class SystemBootTests(unittest.TestCase):
    def test_expected_console(self):
        report = a.inspect_console(START + a.EXPECTED, True)
        self.assertTrue(report["kernel_launched_init"])

    def test_early_exit_rejected(self):
        with self.assertRaisesRegex(ValueError, "exited"):
            a.inspect_console(START + a.EXPECTED, False)

    def test_missing_kernel_launch_rejected(self):
        with self.assertRaisesRegex(ValueError, "kernel evidence"):
            a.inspect_console(a.EXPECTED, True)

    def test_duplicate_marker_rejected(self):
        with self.assertRaisesRegex(ValueError, "exactly one"):
            a.inspect_console(START + a.EXPECTED * 2, True)

    def test_panic_after_marker_rejected(self):
        with self.assertRaisesRegex(ValueError, "panic"):
            a.inspect_console(START + a.EXPECTED + b"Kernel panic - not syncing\n", True)

    def test_missing_marker_rejected(self):
        with self.assertRaisesRegex(ValueError, "marker"):
            a.inspect_console(START, True)

    def test_cpio_contains_exact_init(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            init = root / "init"
            init.write_bytes(fake_aarch64_elf())
            cpio = root / "initramfs.cpio"
            cpio.write_bytes(a.create_archive(init))
            report = a.inspect_cpio(cpio, init)
            self.assertEqual(report["entries_checked"], 6)
            self.assertTrue(report["embedded_init_exact_match"])

    def test_raw_and_gzip_kernel(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "kernel"
            raw = bytearray(128)
            raw[56:60] = b"ARM\x64"
            for data in (bytes(raw), gzip.compress(raw)):
                path.write_bytes(data)
                self.assertEqual(a.kernel_bytes(path), bytes(raw))

    def test_invalid_kernel_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "kernel"
            path.write_bytes(bytes(128))
            with self.assertRaisesRegex(ValueError, "ARM64"):
                a.kernel_bytes(path)


if __name__ == "__main__":
    unittest.main()
