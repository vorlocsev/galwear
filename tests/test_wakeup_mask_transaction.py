"""Offline source checks for PMU wake mask transaction and diagnostic reads."""
from pathlib import Path
import unittest

PATCH = Path(__file__).resolve().parents[1] / "src/kernel/r800-wearos.patch"


def postimage(patch, name):
    diff = patch.split(f"diff --git a/{name} b/{name}\n", 1)[1].split("\ndiff --git ", 1)[0]
    return "\n".join(x[1:] for x in diff.splitlines()
                     if x.startswith((" ", "+")) and not x.startswith("+++"))


class WakeMaskTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        patch = PATCH.read_text(encoding="utf-8")
        cls.mode = postimage(patch, "drivers/soc/samsung/exynos-powermode.c")
        cls.pm = postimage(patch, "drivers/soc/samsung/exynos-pm.c")

    def test_write_and_read_errors_checked(self):
        helper = self.mode.split("static int r800_pmu_write_checked(", 1)[1].split("static int exynos_set_wakeupmask(", 1)[0]
        self.assertEqual(helper.count("return ret < 0 ? ret : -EIO;"), 2)
        self.assertIn("if (actual != val)", helper)

    def test_snapshot_before_system_writes(self):
        self.assertLess(self.mode.index("exynos_pmu_read(off[i], &saved[i])"),
                        self.mode.index("r800_pmu_write_checked(off[i], val[i])"))
        self.assertIn("if (off[j] == off[i])", self.mode)
        self.assertIn("if (off[i] & 3)", self.mode)

    def test_rollback_includes_failed_write_and_continues(self):
        self.assertIn("for (j = i + 1; j > 0; j--)", self.mode)
        self.assertIn("r800_pmu_write_checked(off[j - 1], saved[j - 1])", self.mode)
        self.assertIn("if (err && !rollback)", self.mode)
        self.assertIn("return rollback ? rollback : ret;", self.mode)

    def test_mask_failure_blocks_cal_entry(self):
        self.assertIn("ret = exynos_set_wakeupmask(mode);\n\tif (ret)\n\t\treturn ret;", self.mode)
        self.assertLess(self.mode.index("ret = exynos_set_wakeupmask(mode);"),
                        self.mode.index("ret = cal_pm_enter(mode);"))

    def test_invalid_mode_and_override_rejected(self):
        self.assertIn("(unsigned int)mode >= NUM_SYS_POWERDOWN", self.mode)
        self.assertIn("if (w & ~15)", self.mode)

    def test_dt_bounds_and_readiness(self):
        self.assertIn("pm_info->num_wakeup_mask > R800_MAX_WAKE_MASKS", self.mode)
        self.assertIn("ret > ARRAY_SIZE(exynos_eint_wake_mask_array)", self.mode)
        self.assertIn("if (!ret)\n\t\tr800_masks_ready = true;", self.mode)

    def test_dt_node_ownership(self):
        self.assertIn('of_get_child_by_name(np, "wakeup-masks")', self.mode)
        self.assertIn("of_node_put(child);", self.mode)
        self.assertIn("of_node_put(root);", self.mode)
        self.assertIn("of_node_put(np);", self.mode)

    def test_inform4_errors_never_logged_as_counter(self):
        self.assertEqual(self.pm.count("diag_ret = exynos_pmu_read(CPU_INFORM4, &off_count);"), 2)
        self.assertIn("pre-suspend INFORM4 unavailable", self.pm)
        self.assertIn("post-suspend INFORM4 unavailable", self.pm)
        self.assertIn("MIF down. cur_count: %u, acc_count: %u", self.pm)


if __name__ == "__main__":
    unittest.main()
