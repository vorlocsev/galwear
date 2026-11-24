"""Static checks for independent R800 CPU idle policy."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class CpuIdlePolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        name = "drivers/cpuidle/cpuidle-exynos64.c"
        diff = (ROOT / "src/kernel/r800-wearos.patch").read_text().split(
            f"diff --git a/{name} b/{name}\n", 1)[1].split("\ndiff --git ", 1)[0]
        cls.code = "\n".join(x[1:] for x in diff.splitlines()
                             if x.startswith((" ", "+")) and not x.startswith("+++"))
        cls.helper = (ROOT / "payload/android-helper.sh").read_text()

    def test_default_deny(self):
        self.assertIn("static bool r800_allow_deep_idle;", self.code)

    def test_privileged_gate(self):
        self.assertIn("module_param(r800_allow_deep_idle, bool, 0600);", self.code)

    def test_state_bounds(self):
        self.assertIn("if (index < 0 || index >= drv->state_count)", self.code)

    def test_wfi_fallback(self):
        self.assertIn("if (index > 0 && !READ_ONCE(r800_allow_deep_idle))\n\t\tindex = 0;", self.code)

    def test_notifier_failure_precedes_pmucal(self):
        self.assertLess(self.code.index("ret = cpu_pm_enter();"),
                        self.code.index("entry_state = exynos_cpu_pm_enter(cpu, index);"))
        self.assertIn("return ret < 0 ? ret : -EIO;", self.code)

    def test_policy_change_unwinds_preparation(self):
        self.assertIn("post_idle(dev->cpu, index, 1);\n\t\treturn -EPERM;", self.code)

    def test_positive_psci_result_not_success(self):
        self.assertIn("return ret < 0 ? ret : -EBUSY;", self.code)

    def test_helper_requires_separate_opt_in(self):
        self.assertLess(self.helper.index("if [ -f /oem/r800dev/android/CPUIDLE_DEEP ]"),
                        self.helper.index("printf 'Y\\n' > \"$IDLE_GATE\""))
        self.assertIn('if [ "$IDLE_OK" = 0 ]; then', self.helper)


if __name__ == "__main__":
    unittest.main()
