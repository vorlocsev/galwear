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
BEATS = a.HEARTBEAT_PREFIX + b"00000001\n" + a.HEARTBEAT_PREFIX + b"00000002\n"


PLATFORM = (
    b"[    0.000000] Machine model: linux,dummy-virt\n"
    b"[    0.000000] GICv3: CPU0: found redistributor 0 region 0:0x080a0000\n"
    b"[    0.000000] arch_timer: cp15 timer(s) running at 62.50MHz (virt).\n"
    b"[    0.000000] Memory: 483000K/524288K available (kernel code, reserved)\n"
    b"[    0.100000] GICv3: CPU1: found redistributor 1 region 0:0x080c0000\n"
    b"[    0.110000] SMP: Total of 2 processors activated.\n"
    b"[    0.200000] printk: console [ttyAMA0] enabled\n"
)


class PlatformTests(unittest.TestCase):
    def test_complete_early_platform(self):
        result = a.inspect_platform(PLATFORM + START + a.EXPECTED + BEATS)
        self.assertEqual(result["smp_online_cpus"], 2)
        self.assertEqual(result["gicv3_redistributor_cpus"], [0, 1])
        self.assertEqual(result["arm_timer_mhz_reported"], 62.5)
        self.assertEqual(result["kernel_memory_total_kib"], 524288)
        self.assertTrue(result["pl011_console_enabled"])
        self.assertFalse(result["physical_hardware_verified"])

    def test_each_missing_platform_marker_rejected(self):
        for line in PLATFORM.splitlines(keepends=True):
            with self.subTest(line=line):
                with self.assertRaises(ValueError):
                    a.inspect_platform(PLATFORM.replace(line, b"") + START)

    def test_wrong_machine_rejected(self):
        with self.assertRaisesRegex(ValueError, "machine model"):
            a.inspect_platform(PLATFORM.replace(b"linux,dummy-virt", b"GALILEO-LARGE-BT") + START)

    def test_single_cpu_rejected(self):
        with self.assertRaisesRegex(ValueError, "SMP online"):
            a.inspect_platform(PLATFORM.replace(b"2 processors", b"1 processors") + START)

    def test_duplicate_redistributor_rejected(self):
        with self.assertRaisesRegex(ValueError, "redistributor"):
            a.inspect_platform(PLATFORM.replace(b"CPU1:", b"CPU0:") + START)

    def test_zero_timer_rejected(self):
        with self.assertRaisesRegex(ValueError, "timer frequency"):
            a.inspect_platform(PLATFORM.replace(b"62.50MHz", b"0.00MHz") + START)

    def test_invalid_memory_total_rejected(self):
        with self.assertRaisesRegex(ValueError, "memory total"):
            a.inspect_platform(PLATFORM.replace(b"524288K", b"786432K") + START)

    def test_invalid_available_memory_rejected(self):
        with self.assertRaisesRegex(ValueError, "available memory"):
            a.inspect_platform(PLATFORM.replace(b"483000K", b"100K") + START)

    def test_late_platform_evidence_rejected(self):
        with self.assertRaisesRegex(ValueError, "machine model"):
            a.inspect_platform(START + PLATFORM)

    def test_duplicate_smp_summary_rejected(self):
        with self.assertRaisesRegex(ValueError, "SMP online"):
            a.inspect_platform(PLATFORM + b"SMP: Total of 2 processors activated.\n" + START)


class SystemBootTests(unittest.TestCase):
    def test_expected_console(self):
        report = a.inspect_console(START + a.EXPECTED + BEATS, True)
        self.assertEqual(report["heartbeat_count"], 2)
        self.assertTrue(report["guest_progress_after_marker_verified"])
        self.assertFalse(report["guest_alive_at_timeout_proven"])
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

    def test_missing_heartbeats_rejected(self):
        with self.assertRaisesRegex(ValueError, "Insufficient"):
            a.inspect_console(START + a.EXPECTED, True)

    def test_invalid_heartbeat_sequence_rejected(self):
        for bad in (b"00000001", b"00000003"):
            with self.subTest(bad=bad):
                with self.assertRaisesRegex(ValueError, "sequence"):
                    a.inspect_console(START + a.EXPECTED + BEATS.replace(b"00000002", bad), True)

    def test_heartbeat_before_marker_rejected(self):
        with self.assertRaisesRegex(ValueError, "before startup"):
            a.inspect_console(START + BEATS + a.EXPECTED + BEATS, True)

    def test_critical_diagnostics_rejected_even_after_heartbeats(self):
        for line in (b"Oops: 96000004", b"Internal error: Oops", b"BUG: soft lockup",
                     b"watchdog: hard lockup", b"rcu: INFO: rcu_preempt detected stalls",
                     b"INFO: task init blocked for more than 120 seconds",
                     b"Unable to handle kernel paging request", b"No working init found"):
            with self.subTest(line=line):
                with self.assertRaisesRegex(ValueError, "critical diagnostic"):
                    a.inspect_console(START + a.EXPECTED + BEATS + line + b"\n", True)

    def test_driver_warning_is_reported_not_hidden(self):
        warning = b"[ 2.0] driver probe failed with error -22\n"
        report = a.inspect_console(START + warning + a.EXPECTED + BEATS, True)
        self.assertEqual(report["warning_count"], 1)
        self.assertIn("probe failed", report["warning_samples"][0])
        self.assertFalse(report["critical_diagnostics_detected"])

    def test_live_timing_and_split_lines(self):
        monitor = a.LiveHeartbeat(0)
        monitor.feed(a.EXPECTED[:10], 1)
        monitor.feed(a.EXPECTED[10:], 2)
        first, second = BEATS.splitlines(keepends=True)
        monitor.feed(first, 7)
        monitor.feed(second, 12)
        report = monitor.evidence(15)
        self.assertEqual(report["observed_heartbeat_count"], 2)
        self.assertEqual(report["maximum_observed_gap_seconds"], 5)
        self.assertEqual(report["last_heartbeat_age_seconds"], 3)

    def test_live_startup_timeout(self):
        monitor = a.LiveHeartbeat(0)
        with self.assertRaisesRegex(ValueError, "deadline"):
            monitor.check(a.STARTUP_LIMIT + 1)

    def test_late_startup_marker_rejected(self):
        monitor = a.LiveHeartbeat(0)
        with self.assertRaisesRegex(ValueError, "deadline"):
            monitor.feed(a.EXPECTED, a.STARTUP_LIMIT + 1)

    def test_live_stall_after_two_heartbeats(self):
        monitor = a.LiveHeartbeat(0)
        monitor.feed(a.EXPECTED, 2)
        first, second = BEATS.splitlines(keepends=True)
        monitor.feed(first, 7)
        monitor.feed(second, 12)
        with self.assertRaisesRegex(ValueError, "stalled"):
            monitor.evidence(12 + a.HEARTBEAT_GAP_LIMIT + 1)

    def test_late_heartbeat_cannot_reset_stall(self):
        monitor = a.LiveHeartbeat(0)
        monitor.feed(a.EXPECTED, 1)
        with self.assertRaisesRegex(ValueError, "gap exceeded"):
            monitor.feed(BEATS.splitlines(keepends=True)[0], 2 + a.HEARTBEAT_GAP_LIMIT)

    def test_live_fatal_error_is_immediate(self):
        monitor = a.LiveHeartbeat(0)
        with self.assertRaisesRegex(ValueError, "critical diagnostic"):
            monitor.feed(b"BUG: soft lockup\n", 1)

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
