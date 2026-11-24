"""Offline static regressions for system suspend CAL error propagation."""
from pathlib import Path
import unittest

PATCH = Path(__file__).resolve().parents[1] / "src/kernel/r800-wearos.patch"


def section(patch, name):
    begin = f"diff --git a/{name} b/{name}\n"
    return patch.split(begin, 1)[1].split("\ndiff --git ", 1)[0]


def postimage_hunks(diff):
    return "\n".join(line[1:] for line in diff.splitlines()
                     if line.startswith((" ", "+")) and not line.startswith("+++"))


class SystemSuspendGuardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        patch = PATCH.read_text(encoding="utf-8")
        cls.pm = postimage_hunks(section(patch, "drivers/soc/samsung/exynos-pm.c"))
        cls.mode = postimage_hunks(section(patch, "drivers/soc/samsung/exynos-powermode.c"))
        cls.header = postimage_hunks(section(patch, "include/soc/samsung/exynos-powermode.h"))

    def test_both_prepare_paths_propagate_error(self):
        for field in ("usbl2_suspend_mode_idx", "suspend_mode_idx"):
            self.assertIn(f"r800_pm_mode = pm_info->{field};", self.pm)
        self.assertIn("ret = exynos_prepare_sys_powerdown(r800_pm_mode);", self.pm)
        self.assertIn("return r800_pm_fault;", self.pm)
        self.assertIn("CAL prepare failed", self.pm)

    def test_latched_fault_checked_before_prepare(self):
        self.assertLess(self.pm.index("if (r800_pm_fault)"),
                        self.pm.index("ret = exynos_prepare_sys_powerdown("))
        self.assertEqual(self.pm.count("r800_pm_fault = ret < 0 ? ret : -EIO;"), 2)
        self.assertNotIn("r800_pm_fault = 0", self.pm)

    def test_both_resume_paths_propagate_error(self):
        self.assertIn("ret = exynos_wakeup_sys_powerdown(r800_pm_mode, pm_info->is_early_wakeup);", self.pm)
        self.assertLess(self.pm.index("CAL restore failed"), self.pm.index("R800_MARK(3);"))

    def test_abort_before_psci_defaults_to_early_wakeup(self):
        self.assertIn("r800_psci_attempted = false;", self.pm)
        self.assertIn("if (!r800_psci_attempted)", self.pm)
        self.assertIn("pm_info->is_early_wakeup = true;", self.pm)
        self.assertLess(self.pm.index("r800_psci_attempted = true;"),
                        self.pm.index("ret = arm_cpuidle_suspend(psci_index);"))

    def test_prepared_state_consumed_before_resume(self):
        resume = self.pm.split("static void exynos_pm_syscore_resume(void)", 1)[1]
        self.assertLess(resume.index("if (!r800_pm_prepared)"),
                        resume.index("r800_pm_prepared = false;"))
        self.assertLess(resume.index("r800_pm_prepared = false;"),
                        resume.index("ret = exynos_wakeup_sys_powerdown("))

    def test_psci_error_not_converted_to_positive_bool(self):
        self.assertIn("pm_info->is_early_wakeup = ret != 0;", self.pm)
        self.assertIn("return ret < 0 ? ret : -EBUSY;", self.pm)

    def test_normal_and_early_cal_return_and_header_match(self):
        self.assertIn("ret = cal_pm_earlywakeup(mode);", self.mode)
        self.assertIn("ret = cal_pm_exit(mode);", self.mode)
        self.assertIn("return ret;", self.mode)
        self.assertIn("int exynos_wakeup_sys_powerdown(", self.mode)
        self.assertIn("extern int exynos_wakeup_sys_powerdown(", self.header)


if __name__ == "__main__":
    unittest.main()
