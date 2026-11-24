"""Static offline guards for R800 power-domain rollback; no hardware access."""
from pathlib import Path
import unittest

PATCH = Path(__file__).resolve().parents[1] / "src/kernel/r800-wearos.patch"


class PowerDomainRollbackTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        patch = PATCH.read_text(encoding="utf-8")
        name = "drivers/soc/samsung/exynos-pd.c"
        diff = patch.split(f"diff --git a/{name} b/{name}\n", 1)[1].split("\ndiff --git ", 1)[0]
        cls.code = "\n".join(x[1:] for x in diff.splitlines()
                             if x.startswith("+") and not x.startswith("+++"))

    def block(self, start, stop):
        return self.code.split(start, 1)[1].split(stop, 1)[0]

    def test_cal_return_and_exact_status_both_required(self):
        b = self.block("static int r800_pd_control_checked(", "static int r800_sleep_pds_off(")
        self.assertIn("if (ret || status != (int)on)", b)
        self.assertIn("return ret < 0 ? ret : -EIO;", b)

    def test_invalid_status_not_treated_as_on(self):
        b = self.block("static int r800_sleep_pds_off(", "static int r800_sleep_pds_on(")
        self.assertIn("if (status == 0)", b)
        self.assertIn("if (status != 1)", b)
        self.assertIn("return status < 0 ? status : -EIO;", b)

    def test_attempt_recorded_before_control(self):
        b = self.block("static int r800_sleep_pds_off(", "static int r800_sleep_pds_on(")
        self.assertLess(b.index("r800_sleep_pd_was_on[i] = true"),
                        b.index("r800_pd_control_checked(pd, false)"))

    def test_reverse_unwind_continues_after_error(self):
        b = self.block("static int r800_sleep_pds_on(", "/*\n * Live test")
        self.assertIn("i = ARRAY_SIZE(r800_sleep_pd) - 1; i >= 0; i--", b)
        self.assertIn("if (!first)", b)
        self.assertIn("return first;", b)
        self.assertIn("} else {\n\t\t\tr800_sleep_pd_was_on[i] = false;", b)

    def test_dispaud_restored_before_earlier_domains(self):
        b = self.block("static int r800_pd_restore(", "static int r800_pd_syscore_suspend(")
        self.assertLess(b.index("r800_pd_control_checked(r800_dispaud, true)"),
                        b.index("r800_sleep_pds_on()"))
        self.assertIn("return first ? first : ret;", b)

    def test_clock_restore_requires_power_and_readback(self):
        b = self.block("static int r800_ctrl_opt_restore(", "/*\n * pd-is")
        self.assertIn("cal_pd_status(r800_dispaud->cal_pdid) != 1", b)
        self.assertLess(b.index("readl("), b.index("r800_ctrl_opt_saved = 0"))

    def test_failed_callback_rolls_back_itself_and_latches(self):
        b = self.block("static int r800_pd_syscore_suspend(", "static void r800_pd_syscore_resume(")
        self.assertLess(b.index("if (r800_pd_fault)"), b.index("r800_sleep_pds_off()"))
        self.assertIn("abort:", b)
        self.assertIn("rollback = r800_pd_restore();", b)
        self.assertIn("r800_pd_fault = rollback ? rollback : ret;", b)
        self.assertIn("return r800_pd_fault;", b)

    def test_resume_failure_latches(self):
        b = self.block("static void r800_pd_syscore_resume(", "static struct syscore_ops")
        self.assertIn("int ret = r800_pd_restore();", b)
        self.assertIn("r800_pd_fault = ret;", b)


if __name__ == "__main__":
    unittest.main()
