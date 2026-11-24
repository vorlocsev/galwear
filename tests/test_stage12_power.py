"""Deterministic, offline SM-R800 power-audit and BBD resume regression tests."""
from __future__ import annotations

from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "installer"))
import r800_power_audit as audit


class PowerAuditTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.write("proc/uptime", "1000.00 20.0\n")
        self.write("sys/devices/system/cpu/cpu0/cpuidle/state1/disable", "1\n")
        self.write("sys/devices/system/cpu/cpu0/cpuidle/state1/usage", "10\n")
        self.write("sys/devices/system/cpu/cpu0/cpuidle/state1/time", "5500\n")
        self.write("sys/devices/system/cpu/cpu1/cpuidle/state1/disable", "1\n")
        self.write("sys/devices/system/cpu/cpu1/cpuidle/state1/usage", "15\n")
        self.write("sys/devices/system/cpu/cpu1/cpuidle/state1/time", "6500\n")
        self.write("sys/power/wakeup_count", "88\n")
        self.write("sys/power/wake_lock", "unrelated_kernel_lock r800helper private_lock\n")
        self.write("sys/kernel/debug/suspend_stats",
                   "success: 3\nfail: 1\nfailed_resume: 0\n"
                   "last_failed_dev: SECRET_DEVICE_IDENTIFIER\n")
        self.write("sys/class/power_supply/battery/capacity", "78\n")
        self.write("sys/class/power_supply/battery/status", "Discharging\n")
        self.write("sys/module/exynos_pd/parameters/r800_sleep_pd_off", "0\n")

    def write(self, relative, value):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value, encoding="utf-8")

    def test_snapshot_only_includes_whitelisted_metrics(self):
        s = audit.snapshot(self.root)
        self.assertEqual(s["metrics"]["cpu0_state1_disable"], 1)
        self.assertEqual(s["metrics"]["battery_capacity_percent"], 78)
        self.assertEqual(s["metrics"]["pd_off_mask"], 0)
        self.assertEqual(s["suspend_stats"]["success"], 3)
        self.assertTrue(s["power_modes"]["r800helper_lock_seen"])
        self.assertFalse(s["hardware_stability_verified"])
        self.assertFalse(s["writes_to_device"])
        self.assertFalse(s["suspend_performed"])
        text = json.dumps(s)
        self.assertNotIn("SECRET_DEVICE_IDENTIFIER", text)
        self.assertNotIn("unrelated_kernel_lock", text)
        self.assertNotIn("private_lock", text)

    def test_no_flags_default_to_safe_configuration(self):
        s = audit.snapshot(self.root)
        self.assertFalse(s["power_modes"]["sleep_opt_in"])
        self.assertFalse(s["power_modes"]["cpuidle_deep_opt_in"])

    def test_sleep_and_deep_idle_flags_are_independent(self):
        self.write("oem/r800dev/android/SLEEP", "")
        s = audit.snapshot(self.root)
        self.assertTrue(s["power_modes"]["sleep_opt_in"])
        self.assertFalse(s["power_modes"]["cpuidle_deep_opt_in"])
        self.write("oem/r800dev/android/CPUIDLE_DEEP", "")
        s = audit.snapshot(self.root)
        self.assertTrue(s["power_modes"]["cpuidle_deep_opt_in"])

    def test_non_numeric_node_never_leaks_raw_text(self):
        self.write("sys/power/wakeup_count", "SERIAL_123456\n")
        s = audit.snapshot(self.root)
        self.assertNotIn("wakeup_count", s["metrics"])
        self.assertIn("wakeup_count", s["unavailable"])
        self.assertNotIn("SERIAL_123456", json.dumps(s))

    def test_symlink_escape_never_reads_host_secret(self):
        p = self.root / "sys/power/wakeup_count"
        p.unlink()
        try:
            p.symlink_to("/etc/passwd")
        except (OSError, NotImplementedError):
            self.skipTest("Symlinks unavailable")
        s = audit.snapshot(self.root)
        self.assertNotIn("wakeup_count", s["metrics"])
        self.assertIn("wakeup_count", s["unavailable"])

    def test_battery_status_allowlist_excludes_private_text(self):
        self.write("sys/class/power_supply/battery/status", "SERIAL_ID_PRIVATE\n")
        s = audit.snapshot(self.root)
        self.assertIsNone(s["battery_status"])
        self.assertNotIn("SERIAL_ID_PRIVATE", json.dumps(s))

    def test_synthetic_counters_compare(self):
        before = audit.snapshot(self.root)
        self.write("proc/uptime", "1030.0 20.0\n")
        self.write("sys/power/wakeup_count", "90\n")
        self.write("sys/devices/system/cpu/cpu0/cpuidle/state1/usage", "17\n")
        self.write("sys/kernel/debug/suspend_stats", "success: 4\nfail: 1\n")
        after = audit.snapshot(self.root)
        report = audit.compare(before, after)
        self.assertEqual(report["deltas"]["wakeup_count"], 2)
        self.assertEqual(report["deltas"]["cpu0_state1_usage"], 7)
        self.assertEqual(report["deltas"]["suspend_success"], 1)
        self.assertFalse(report["hardware_stability_verified"])
        self.assertFalse(report["reboot_detected"])

    def test_reboot_invalidates_counter_deltas(self):
        before = audit.snapshot(self.root)
        self.write("proc/uptime", "15.0 10.0\n")
        after = audit.snapshot(self.root)
        out = audit.compare(before, after)
        self.assertTrue(out["reboot_detected"])
        self.assertIsNone(out["deltas"]["wakeup_count"])

    def test_policy_change_marked_non_comparable(self):
        before = audit.snapshot(self.root)
        self.write("oem/r800dev/android/SLEEP", "")
        after = audit.snapshot(self.root)
        report = audit.compare(before, after)
        self.assertTrue(report["power_modes_changed"])

    def test_bad_schema_rejected(self):
        with self.assertRaises(ValueError):
            audit.compare({"schema": "unrelated"}, audit.snapshot(self.root))

    def test_missing_sysfs_is_reported_not_fatal(self):
        with tempfile.TemporaryDirectory() as empty:
            s = audit.snapshot(Path(empty))
        self.assertEqual(s["metrics"], {})
        self.assertIn("suspend_stats", s["unavailable"])

    def test_snapshot_and_compare_cli_are_offline(self):
        one = self.root / "snapshot_before.json"
        two = self.root / "snapshot_after.json"
        result = self.root / "comparison.json"
        with mock.patch("socket.socket", side_effect=AssertionError("Network forbidden")):
            with redirect_stdout(io.StringIO()):
                self.assertEqual(audit.main([
                    "snapshot", "--root", str(self.root), "--output", str(one)]), 0)
            self.write("proc/uptime", "1005.0 25.0\n")
            with redirect_stdout(io.StringIO()):
                self.assertEqual(audit.main([
                    "snapshot", "--root", str(self.root), "--output", str(two)]), 0)
                self.assertEqual(audit.main([
                    "compare", "--before", str(one), "--after", str(two),
                    "--output", str(result)]), 0)
        self.assertFalse(json.loads(result.read_text())["hardware_stability_verified"])

    def test_kernel_bbd_callback_guard_checks_correct_method(self):
        patch = (ROOT / "src/kernel/r800-wearos.patch").read_text(encoding="utf-8")
        start = patch.index("+static int bbd_resume(void)")
        end = patch.index("+static int bbd_notifier", start)
        block = patch[start:end]
        self.assertIn("pssp_driver->driver.pm->resume)", block)
        self.assertIn("pssp_driver &&", block)
        self.assertNotIn("pssp_driver->driver.pm->suspend)", block)
        self.assertIn("+\t\tpssp_driver->driver.pm->resume(&dummy_spi.dev);", block)

    def test_kernel_suspend_callback_keeps_its_own_guard(self):
        patch = (ROOT / "src/kernel/r800-wearos.patch").read_text(encoding="utf-8")
        start = patch.index("+static int bbd_suspend(pm_message_t state)")
        end = patch.index("+static int bbd_resume(void)", start)
        suspend = patch[start:end]
        self.assertIn("pssp_driver->driver.pm->suspend)", suspend)


if __name__ == "__main__":
    unittest.main()
