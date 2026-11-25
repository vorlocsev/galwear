"""Synthetic trace parser tests for numbered init heartbeats."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "build"))
import r800_qemu_user_init as a

def write(size):
    return f"123 write(1,0x400000,{size}) = {size}\n".encode()

WRITE = write(len(a.EXPECTED))
BEAT_WRITE = write(a.HEARTBEAT_BYTES)
SLEEP = b"123 nanosleep(0x400100,NULL) = 0\n"
PENDING = b"123 nanosleep(0x400100,NULL)"
OUT = a.EXPECTED + a.HEARTBEAT_PREFIX + b"00000001\n" + a.HEARTBEAT_PREFIX + b"00000002\n"
TRACE = WRITE + (SLEEP + BEAT_WRITE) * 2 + PENDING


class QemuTraceTests(unittest.TestCase):
    def test_expected_message_and_completed_sleep(self):
        report = a.inspect_trace(OUT, TRACE, True)
        self.assertTrue(report["completed_nanosleep"])
        self.assertEqual(report["heartbeat_count"], 2)

    def test_unexpected_exit(self):
        with self.assertRaisesRegex(ValueError, "exited"):
            a.inspect_trace(OUT, TRACE, False)

    def test_missing_message(self):
        with self.assertRaisesRegex(ValueError, "console message"):
            a.inspect_trace(b"", TRACE, True)

    def test_unexpected_syscall(self):
        with self.assertRaisesRegex(ValueError, "Unexpected guest syscall"):
            a.inspect_trace(OUT, WRITE + b"123 openat(-100,0x400000,0) = 3\n" + SLEEP, True)

    def test_wrong_write_descriptor(self):
        with self.assertRaisesRegex(ValueError, "write syscall"):
            a.inspect_trace(OUT, TRACE.replace(b"write(1,", b"write(2,", 1), True)

    def test_failed_sleep(self):
        with self.assertRaisesRegex(ValueError, "nanosleep failure"):
            a.inspect_trace(OUT, TRACE.replace(b" = 0", b" = -1", 1), True)

    def test_insufficient_heartbeats(self):
        with self.assertRaisesRegex(ValueError, "Insufficient"):
            a.inspect_trace(a.EXPECTED, WRITE + PENDING, True)

    def test_duplicate_write(self):
        with self.assertRaisesRegex(ValueError, "without successful sleep"):
            a.inspect_trace(OUT, WRITE + BEAT_WRITE + SLEEP, True)

    def test_unknown_trace_line(self):
        with self.assertRaisesRegex(ValueError, "Unrecognized"):
            a.inspect_trace(OUT, WRITE + SLEEP + b"unexpected diagnostic\n", True)

    def test_skipped_or_duplicate_heartbeat(self):
        for invalid in (b"00000001", b"00000003"):
            with self.subTest(invalid=invalid):
                with self.assertRaisesRegex(ValueError, "sequence"):
                    a.inspect_trace(OUT.replace(b"00000002", invalid), TRACE, True)

    def test_trace_missing_heartbeat_write(self):
        with self.assertRaisesRegex(ValueError, "disagree"):
            a.inspect_trace(OUT, WRITE + SLEEP + BEAT_WRITE, True)


if __name__ == "__main__":
    unittest.main()
