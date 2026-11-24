"""Host-only synthetic display watchdog checks. Never run Android helper."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "payload/r800-display-watchdog.sh"


class DisplayWatchdogTests(unittest.TestCase):
    def invoke(self, fn, *args):
        return subprocess.run(["sh", "-c", 'B=; . "$1"; shift; "$@"',
                               "test", str(HELPER), fn, *map(str, args)],
                              capture_output=True, text=True, timeout=5)

    def fixture(self, text, fn, *args):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "fixture"
            p.write_text(text)
            return self.invoke(fn, p, *args)

    def test_irq_sum_all_cpus(self):
        result = self.fixture(" CPU0 CPU1\n 42: 5 27 GIC decon_f\n",
                              "r800_irq_total")
        self.assertEqual((result.returncode, result.stdout.strip()), (0, "32"))

    def test_irq_missing_ambiguous_or_invalid(self):
        for text in (" CPU0 CPU1\n 42: 1 2 GIC other\n",
                     " CPU0 CPU1\n 42: 1 2 GIC decon_f0\n 43: 2 3 GIC decon_f1\n",
                     " CPU0 CPU1\n 42: 1 x GIC decon_f\n"):
            with self.subTest(text=text):
                self.assertNotEqual(self.fixture(text, "r800_irq_total").returncode, 0)

    def test_pid_stat_with_spaces_and_parentheses(self):
        fields = ["S"] + ["0"] * 18 + ["12345", "0"]
        result = self.fixture("42 (foo ) bar) " + " ".join(fields) + "\n",
                              "r800_process_start_ticks", 42)
        self.assertEqual((result.returncode, result.stdout.strip()), (0, "12345"))

    def test_wrong_pid_and_truncated_stat(self):
        for text in ("43 (x) S " + "0 " * 25, "42 (x) S 0"):
            self.assertNotEqual(self.fixture(text, "r800_process_start_ticks", 42).returncode, 0)

    def test_uptime(self):
        result = self.fixture("122.75 91.00\n", "r800_uptime_seconds")
        self.assertEqual((result.returncode, result.stdout.strip()), (0, "122"))

    def test_valid_restart_and_zero_copy_reboot(self):
        for mode, expected in (("0", "restart"), ("1", "reboot"), ("", "reboot")):
            r = self.invoke("r800_hwc_action", 150, 140, 130, 0, 100, mode)
            self.assertEqual((r.returncode, r.stdout.strip()), (0, expected))

    def test_stale_future_and_young_process(self):
        for args in ((150, 130, 130, 0, 100, 1),
                     (150, 151, 130, 0, 100, 1),
                     (150, 147, 130, 0, 100, 1),
                     (150, 140, 130, 0, 12, 1),
                     (150, 140, 130, 120, 100, 1)):
            self.assertNotEqual(self.invoke("r800_hwc_action", *args).returncode, 0)

    def test_reject_ambiguous_numeric_inputs(self):
        for bad in ("", "1 2", "-1", "010", "1234567890123", "abc"):
            self.assertNotEqual(self.invoke("r800_hwc_action", 150, bad, 130, 0, 100, 1).returncode, 0)
        self.assertNotEqual(self.invoke("r800_hwc_action", 150, 140, 130, 0, 100, "unknown").returncode, 0)

    def test_shell_syntax_and_packaging(self):
        for path in (HELPER, ROOT / "payload/android-helper.sh", ROOT / "build/mkpayload-release.sh"):
            subprocess.run(["sh", "-n", str(path)], check=True, timeout=5)
        self.assertIn("r800-display-watchdog.sh", (ROOT / "build/mkpayload-release.sh").read_text())


if __name__ == "__main__":
    unittest.main()
