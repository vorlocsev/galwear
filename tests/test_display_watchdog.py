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

    def test_restart_requires_explicit_cpu_copy_opt_in(self):
        for mode in ("0", "1", ""):
            for opt in (0, 1):
                with self.subTest(mode=mode, opt=opt):
                    expected = "restart" if mode == "0" and opt == 1 else "observe"
                    r = self.invoke("r800_hwc_action", 150, 140, 130, 0, 100, mode, opt)
                    self.assertEqual((r.returncode, r.stdout.strip()), (0, expected))

    def test_second_attempt_never_escalates(self):
        r = self.invoke("r800_hwc_action", 250, 240, 230, 150, 100, 0, 1)
        self.assertEqual((r.returncode, r.stdout.strip()), (0, "observe"))

    def test_no_reboot_or_deadman_disarm_in_display_watchdog(self):
        source = (ROOT / "payload/android-helper.sh").read_text()
        block = source[source.index("    # Display watchdog is diagnostic"):
                       source.index("    # Developer mode: post-boot logcat")]
        for forbidden in ("/proc/sysrq-trigger", "kill $PETTER", "kill -KILL", "reboot"):
            # Comments explain why reboot was removed; inspect executable lines.
            commands = "\n".join(line for line in block.splitlines()
                                 if not line.lstrip().startswith("#"))
            self.assertNotIn(forbidden, commands)
        self.assertIn('$B mkdir "$HWCATTEMPT"', block)
        self.assertIn('kill -TERM "$cp"', block)
        import sys
        sys.path.insert(0, str(ROOT / "build"))
        from r800_payload_candidate import STATE, NEVER_SHIP_ANDROID_FILES
        self.assertIn("HWC_RESTART", STATE)
        self.assertIn("HWC_RESTART", NEVER_SHIP_ANDROID_FILES)

    def test_stale_future_and_young_process(self):
        for args in ((150, 130, 130, 0, 100, 1),
                     (150, 151, 130, 0, 100, 1),
                     (150, 147, 130, 0, 100, 1),
                     (150, 140, 130, 0, 12, 1),
                     (150, 140, 130, 120, 100, 1)):
            self.assertNotEqual(self.invoke("r800_hwc_action", *args, 1).returncode, 0)

    def test_reject_ambiguous_numeric_inputs(self):
        for bad in ("", "1 2", "-1", "010", "1234567890123", "abc"):
            self.assertNotEqual(self.invoke("r800_hwc_action", 150, bad, 130, 0, 100, 1, 1).returncode, 0)
        self.assertNotEqual(self.invoke("r800_hwc_action", 150, 140, 130, 0, 100, "unknown", 1).returncode, 0)
        self.assertNotEqual(self.invoke("r800_hwc_action", 150, 140, 130, 0, 100, 0, "unknown").returncode, 0)

    def test_shell_syntax_and_packaging(self):
        for path in (HELPER, ROOT / "payload/android-helper.sh", ROOT / "build/mkpayload-release.sh"):
            subprocess.run(["sh", "-n", str(path)], check=True, timeout=5)
        import sys
        sys.path.insert(0, str(ROOT / "build"))
        from r800_payload_candidate import SCRIPTS
        self.assertIn("r800-display-watchdog.sh", SCRIPTS)


if __name__ == "__main__":
    unittest.main()
