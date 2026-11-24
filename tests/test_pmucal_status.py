"""Offline static checks for PMUCAL status propagation and genpd callers."""
from pathlib import Path
import unittest

PATCH = Path(__file__).resolve().parents[1] / "src/kernel/r800-wearos.patch"


def section(patch, name):
    return patch.split(f"diff --git a/{name} b/{name}\n", 1)[1].split("\ndiff --git ", 1)[0]


def postimage(diff):
    return "\n".join(x[1:] for x in diff.splitlines()
                     if x.startswith((" ", "+")) and not x.startswith("+++"))


class PmucalStatusTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        patch = PATCH.read_text(encoding="utf-8")
        cls.local = postimage(section(patch, "drivers/soc/samsung/cal-if/pmucal_local.c"))
        cls.pd = postimage(section(patch, "drivers/soc/samsung/exynos-pd.c"))

    def test_missing_or_empty_status_rejected(self):
        self.assertIn("!pmucal_pd_list[pd_id].status || !pmucal_pd_list[pd_id].num_status", self.local)
        self.assertIn("return -ENOENT;", self.local)

    def test_sequence_result_checked_before_status_comparison(self):
        self.assertLess(self.local.index("ret = pmucal_rae_handle_seq("),
                        self.local.index("if (ret)"))
        self.assertLess(self.local.index("return ret < 0 ? ret : -EIO;"),
                        self.local.index("for (i = 0; i < pmucal_pd_list[pd_id].num_status; i++)"))

    def test_bcm_requires_confirmed_on(self):
        self.assertEqual(self.pd.count("if (cal_pd_status(pd->cal_pdid) == 1 && pd->bcm)"), 2)

    def test_power_on_rejects_unknown_state_before_fast_path(self):
        guard = "status = cal_pd_status(pd->cal_pdid);\n\tif (status != 0 && status != 1)"
        self.assertIn(guard, self.pd)
        self.assertIn("if (status == 1) {", self.pd)
        self.assertLess(self.pd.index(guard), self.pd.index("if (status == 1) {"))

    def test_power_off_rejects_unknown_state_before_fast_path(self):
        guard = "status = cal_pd_status(pd->cal_pdid);\n\tif (status != 0 && status != 1)"
        self.assertEqual(self.pd.count(guard), 2)
        self.assertLess(self.pd.rindex(guard), self.pd.index("if (status == 0) {"))

    def test_probe_accepts_only_binary_state(self):
        self.assertIn("if (initial_state != 0 && initial_state != 1)", self.pd)
        self.assertIn("return initial_state < 0 ? initial_state : -EIO;", self.pd)

    def test_probe_log_does_not_repeat_status_read(self):
        self.assertIn('initial_state == 1 ? "on" : "off"', self.pd)
        self.assertNotIn('cal_pd_status(pd->cal_pdid) ? "on" : "off"', self.pd)

    def test_prior_syscore_guard_preserved(self):
        self.assertIn("if (ret || status != (int)on)", self.pd)
        self.assertIn("rollback = r800_pd_restore();", self.pd)


if __name__ == "__main__":
    unittest.main()
