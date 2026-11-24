"""Offline regressions for ACPM MIF checked access and suspend gating."""
from pathlib import Path
import unittest

PATCH = Path(__file__).resolve().parents[1] / "src/kernel/r800-wearos.patch"


def postimage(patch, name):
    diff = patch.split(f"diff --git a/{name} b/{name}\n", 1)[1].split("\ndiff --git ", 1)[0]
    return "\n".join(x[1:] for x in diff.splitlines()
                     if x.startswith((" ", "+")) and not x.startswith("+++"))


class AcpmMifTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        patch = PATCH.read_text(encoding="utf-8")
        cls.dbg = postimage(patch, "drivers/soc/samsung/exynos-flexpmu-dbg.c")
        cls.pm = postimage(patch, "drivers/soc/samsung/exynos-pm.c")
        cls.header = postimage(patch, "include/soc/samsung/exynos-pm.h")
        cls.read = cls.dbg.split("int acpm_read_mif_state(", 1)[1].split("EXPORT_SYMBOL_GPL(acpm_read_mif_state)", 1)[0]

    def test_invalid_outputs_rejected(self):
        self.assertIn("if (!count || !request || count == request)", self.read)

    def test_missing_mapping_and_bounds_before_mmio(self):
        for guard in ("if (!r800_mif_base)", "r800_mif_size < R800_MIF_COUNT_OFF + sizeof(u32)",
                      "r800_mif_size < R800_MIF_REQ_OFF + sizeof(u32)"):
            self.assertLess(self.read.index(guard), self.read.index("__raw_readl("))
        self.assertIn("ret = -ENODEV;", self.read)
        self.assertIn("ret = -ERANGE;", self.read)

    def test_irq_safe_snapshot(self):
        self.assertLess(self.read.index("spin_lock_irqsave("), self.read.index("__raw_readl("))
        self.assertLess(self.read.index("*request ="), self.read.index("spin_unlock_irqrestore("))

    def test_probe_checks_mapping_and_dt_size(self):
        self.assertEqual(self.dbg.count("if (!prop || len != sizeof(*prop))"), 2)
        self.assertIn("data_size < DATA_LINE * DID_MAX", self.dbg)
        self.assertIn("if (!flexpmu_dbg_base)", self.dbg)
        self.assertIn("r800_mif_size = data_size;", self.dbg)

    def test_remove_invalidates_checked_mapping(self):
        self.assertIn("r800_mif_base = NULL;", self.dbg)
        self.assertIn("r800_mif_size = 0;", self.dbg)

    def test_missing_acpm_config_returns_error(self):
        self.assertIn("return -EOPNOTSUPP;", self.header)

    def test_pre_failure_prevents_psci_and_post_preserves_psci_error(self):
        self.assertLess(self.pm.index("pre-suspend ACPM state unavailable"),
                        self.pm.index("ret = arm_cpuidle_suspend(psci_index);"))
        self.assertIn("return ret ? (ret < 0 ? ret : -EBUSY) : mif_ret;", self.pm)

    def test_counter_delta_is_conservative(self):
        self.assertIn("if (post_mif - prev_mif > 1)", self.pm)
        self.assertIn("if (post_mif == prev_mif)", self.pm)
        delta = lambda before, after: (after - before) & 0xffffffff
        self.assertEqual(delta(0xffffffff, 0), 1)
        self.assertEqual(delta(3, 3), 0)
        self.assertGreater(delta(100, 0), 1)


if __name__ == "__main__":
    unittest.main()
