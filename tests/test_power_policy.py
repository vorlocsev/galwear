"""Offline policy tests. Never connect to a watch or write device sysfs."""
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "payload" / "android-helper.sh"


class PowerPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.script = HELPER.read_text(encoding="utf-8")

    def test_full_helper_shell_syntax(self):
        run = subprocess.run(["sh", "-n", str(HELPER)], capture_output=True, text=True)
        self.assertEqual(run.returncode, 0, run.stderr)

    def test_two_distinct_opt_ins(self):
        self.assertIn('SLEEPF=/oem/r800dev/android/SLEEP', self.script)
        self.assertIn('/oem/r800dev/android/CPUIDLE_DEEP', self.script)
        self.assertIn('echo 1 > "$IDLE"', self.script)
        self.assertIn('echo 0 > "$IDLE"', self.script)

    def _simulate(self, suspend_enabled, idle_enabled):
        text = self.script
        start = text.index("SLEEPF=/oem/r800dev/android/SLEEP")
        stop = text.index("\n# Composer DECON", start)
        suspend_block = text[start:stop]
        start = text.index("    # CPU deep-idle is independent of system suspend.")
        stop = text.index("\n    done", start) + len("\n    done")
        idle_block = text[start:stop]

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for cpu in ("cpu0", "cpu1"):
                (root / cpu).mkdir()
                (root / cpu / "disable").write_text("9", encoding="ascii")
            if suspend_enabled:
                (root / "SLEEP").touch()
            if idle_enabled:
                (root / "CPUIDLE_DEEP").touch()
            wake = root / "wake_lock"
            wake.write_text("", encoding="ascii")

            # Replace only device paths in the isolated policy snippet.
            snippet = "k() { :; }\n" + suspend_block + "\n" + idle_block + "\n"
            snippet = snippet.replace("/oem/r800dev/android/SLEEP", str(root / "SLEEP"))
            snippet = snippet.replace("/oem/r800dev/android/CPUIDLE_DEEP", str(root / "CPUIDLE_DEEP"))
            snippet = snippet.replace("/sys/power/wake_lock", str(wake))
            snippet = snippet.replace(
                'IDLE=/sys/devices/system/cpu/cpu$c/cpuidle/state1/disable',
                f'IDLE={root}/cpu$c/disable')
            run = subprocess.run(["sh", "-eu"], input=snippet,
                                 capture_output=True, text=True)
            self.assertEqual(run.returncode, 0, run.stderr)
            return wake.read_text(encoding="ascii").strip(), [
                (root / cpu / "disable").read_text(encoding="ascii").strip()
                for cpu in ("cpu0", "cpu1")
            ]

    def test_all_four_power_modes_are_independent(self):
        for suspend in (False, True):
            for idle in (False, True):
                with self.subTest(suspend=suspend, idle=idle):
                    wake, disable = self._simulate(suspend, idle)
                    self.assertEqual(wake, "" if suspend else "r800helper")
                    self.assertEqual(disable, ["0", "0"] if idle else ["1", "1"])


if __name__ == "__main__":
    unittest.main()
