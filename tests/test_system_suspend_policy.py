"""Offline guards for experimental system suspend; no device access."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class SuspendPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        name = "drivers/soc/samsung/exynos-pm.c"
        diff = (ROOT / "src/kernel/r800-wearos.patch").read_text().split(
            f"diff --git a/{name} b/{name}\n", 1)[1].split("\ndiff --git ", 1)[0]
        cls.pm = "\n".join(x[1:] for x in diff.splitlines()
                           if x.startswith((" ", "+")) and not x.startswith("+++"))
        cls.helper = (ROOT / "payload/android-helper.sh").read_text()

    def test_default_deny(self):
        self.assertIn("static bool r800_allow_system_suspend;", self.pm)

    def test_privileged_parameter(self):
        self.assertIn("module_param(r800_allow_system_suspend, bool, 0600);", self.pm)

    def test_begin_before_device_suspend(self):
        self.assertIn(".begin\t\t= r800_suspend_begin,", self.pm)

    def test_syscore_guard(self):
        self.assertLess(self.pm.index("if (!READ_ONCE(r800_allow_system_suspend))"),
                        self.pm.index("ret = exynos_prepare_sys_powerdown(r800_pm_mode);"))

    def test_psci_guard(self):
        self.assertLess(self.pm.index("ret = r800_suspend_policy();"),
                        self.pm.index("ret = arm_cpuidle_suspend(psci_index);"))

    def test_wakelock_first(self):
        self.assertLess(self.helper.index("echo r800helper > /sys/power/wake_lock"),
                        self.helper.index("r800_set_suspend_gate Y Y"))

    def test_gate_before_unlock(self):
        self.assertLess(self.helper.index("r800_set_suspend_gate Y Y"),
                        self.helper.index("echo r800helper > /sys/power/wake_unlock"))

    def test_failed_optin_resets_overrides(self):
        self.assertIn('if [ "$SLEEP_ENABLED" = 0 ]; then', self.helper)
        self.assertIn("refusing experimental opt-in", self.helper)
        self.assertIn("r800_set_suspend_gate N N", self.helper)


if __name__ == "__main__":
    unittest.main()
