"""Synthetic trace parser regression tests (real execution is a separate CI step)."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "build"))
import r800_qemu_user_init as a

N = len(a.EXPECTED)
WRITE = f"123 write(1,0x400000,{N}) = {N}\n".encode()
SLEEP = b"123 nanosleep(0x400100,NULL) = 0\n"
PENDING = b"123 nanosleep(0x400100,NULL)"


class QemuTraceTests(unittest.TestCase):
    def test_expected_message_and_completed_sleep(self):
        report = a.inspect_trace(a.EXPECTED, WRITE + SLEEP + PENDING, True)
        self.assertTrue(report["completed_nanosleep"])
        self.assertEqual(report["observed_guest_syscalls"], ["write", "nanosleep", "nanosleep"])

    def test_unexpected_exit(self):
        with self.assertRaisesRegex(ValueError, "exited"):
            a.inspect_trace(a.EXPECTED, WRITE + SLEEP, False)

    def test_missing_message(self):
        with self.assertRaisesRegex(ValueError, "console message"):
            a.inspect_trace(b"", WRITE + SLEEP, True)

    def test_unexpected_syscall(self):
        with self.assertRaisesRegex(ValueError, "Unexpected guest syscall"):
            a.inspect_trace(a.EXPECTED, WRITE + b"123 openat(-100,0x400000,0) = 3\n" + SLEEP, True)

    def test_wrong_write_descriptor(self):
        with self.assertRaisesRegex(ValueError, "write syscall"):
            a.inspect_trace(a.EXPECTED, WRITE.replace(b"write(1,", b"write(2,") + SLEEP, True)

    def test_failed_sleep(self):
        with self.assertRaisesRegex(ValueError, "nanosleep failure"):
            a.inspect_trace(a.EXPECTED, WRITE + SLEEP.replace(b" = 0", b" = -1"), True)

    def test_incomplete_sleep(self):
        with self.assertRaisesRegex(ValueError, "completed sleep"):
            a.inspect_trace(a.EXPECTED, WRITE + PENDING, True)

    def test_duplicate_write(self):
        with self.assertRaisesRegex(ValueError, "one console write"):
            a.inspect_trace(a.EXPECTED, WRITE + WRITE + SLEEP, True)

    def test_unknown_trace_line(self):
        with self.assertRaisesRegex(ValueError, "Unrecognized"):
            a.inspect_trace(a.EXPECTED, WRITE + SLEEP + b"unexpected diagnostic\n", True)


if __name__ == "__main__":
    unittest.main()
