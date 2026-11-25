"""Exercise the real suspend and idle snippets using temporary files only."""
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
        subprocess.run(["sh", "-n", str(HELPER)], check=True, timeout=5)

    def _simulate(self, suspend, idle, missing_suspend=False, missing_idle=False,
                  broken_pd=False, broken_cpu=False):
        start = self.script.index("SLEEPF=/oem/r800dev/android/SLEEP")
        end = self.script.index("\n# Composer DECON", start)
        suspend_block = self.script[start:end]
        start = self.script.index("    IDLE_GATE=/sys/module/cpuidle_exynos64/")
        end = self.script.index("\n    # /data is only", start)
        idle_block = self.script[start:end]
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            initial = {"wake_lock": "", "wake_unlock": "", "suspend": "N",
                       "pd": "0", "dispaud": "N", "idle": "N",
                       "cpu0/disable": "9", "cpu1/disable": "9"}
            for name, value in initial.items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                if ((name == "suspend" and missing_suspend) or
                    (name == "idle" and missing_idle)):
                    continue
                if ((name == "pd" and broken_pd) or
                    (name == "cpu1/disable" and broken_cpu)):
                    path.mkdir()
                else:
                    path.write_text(value)
            for flag, name in ((suspend, "SLEEP"), (idle, "CPUIDLE_DEEP")):
                if flag:
                    (root / name).touch()
            snippet = suspend_block + "\n" + idle_block
            mapping = {
                "/oem/r800dev/android/": str(root) + "/",
                "/sys/power/wake_lock": str(root / "wake_lock"),
                "/sys/power/wake_unlock": str(root / "wake_unlock"),
                "/sys/module/exynos_pm/parameters/r800_allow_system_suspend": str(root / ("absent-suspend/gate" if missing_suspend else "suspend")),
                "/sys/module/exynos_pd/parameters/r800_sleep_pd_off": str(root / "pd"),
                "/sys/module/exynos_pd/parameters/r800_dispaud_sleep_off": str(root / "dispaud"),
                "/sys/module/cpuidle_exynos64/parameters/r800_allow_deep_idle": str(root / ("absent-idle/gate" if missing_idle else "idle")),
                "/sys/devices/system/cpu/cpu$c/cpuidle/state1/disable": str(root) + "/cpu$c/disable",
            }
            for source, target in mapping.items():
                snippet = snippet.replace(source, target)
            self.assertNotIn("/sys/", snippet)
            self.assertNotIn("/oem/", snippet)
            run = subprocess.run(["sh", "-eu"], input="B=; k() { :; }\n" + snippet,
                                 capture_output=True, text=True, timeout=5)
            self.assertEqual(run.returncode, 0, run.stderr)
            return {name: (root / name).read_text().strip()
                    if (root / name).is_file() else None for name in initial}

    def test_all_four_power_modes_are_independent(self):
        for suspend in (False, True):
            for idle in (False, True):
                with self.subTest(suspend=suspend, idle=idle):
                    state = self._simulate(suspend, idle)
                    self.assertEqual(state, {
                        "wake_lock": "r800helper",
                        "wake_unlock": "r800helper" if suspend else "",
                        "suspend": "Y" if suspend else "N",
                        "pd": "3" if suspend else "0",
                        "dispaud": "Y" if suspend else "N",
                        "idle": "Y" if idle else "N",
                        "cpu0/disable": "0" if idle else "1",
                        "cpu1/disable": "0" if idle else "1",
                    })

    def test_missing_suspend_gate_never_unlocks(self):
        state = self._simulate(True, True, missing_suspend=True)
        self.assertIsNone(state["suspend"])
        self.assertEqual(state["wake_unlock"], "")
        self.assertEqual(state["pd"], "0")
        self.assertEqual(state["dispaud"], "N")
        self.assertEqual(state["idle"], "Y")

    def test_failed_pd_opt_in_keeps_suspend_guarded(self):
        state = self._simulate(True, False, broken_pd=True)
        self.assertEqual(state["suspend"], "N")
        self.assertEqual(state["wake_lock"], "r800helper")
        self.assertEqual(state["wake_unlock"], "")
        self.assertEqual(state["dispaud"], "N")

    def test_missing_idle_gate_keeps_both_cpus_disabled(self):
        state = self._simulate(True, True, missing_idle=True)
        self.assertIsNone(state["idle"])
        self.assertEqual(state["cpu0/disable"], "1")
        self.assertEqual(state["cpu1/disable"], "1")
        self.assertEqual(state["suspend"], "Y")

    def test_partial_idle_opt_in_rolls_back(self):
        state = self._simulate(False, True, broken_cpu=True)
        self.assertEqual(state["idle"], "N")
        self.assertEqual(state["cpu0/disable"], "1")
        self.assertIsNone(state["cpu1/disable"])


if __name__ == "__main__":
    unittest.main()
