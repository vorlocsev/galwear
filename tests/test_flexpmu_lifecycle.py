"""Static lifecycle checks against the pinned Linux 4.19 patch."""
from pathlib import Path
import unittest

PATCH = Path(__file__).resolve().parents[1] / "src/kernel/r800-wearos.patch"


class FlexpmuLifecycleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        name = "drivers/soc/samsung/exynos-flexpmu-dbg.c"
        diff = PATCH.read_text(encoding="utf-8").split(
            f"diff --git a/{name} b/{name}\n", 1)[1].split("\ndiff --git ", 1)[0]
        cls.code = "\n".join(x[1:] for x in diff.splitlines()
                             if x.startswith((" ", "+")) and not x.startswith("+++"))
        cls.probe = cls.code.split("static int exynos_flexpmu_dbg_probe(", 1)[1].split(
            "static int exynos_flexpmu_dbg_remove(", 1)[0]
        cls.remove = cls.code.split("static int exynos_flexpmu_dbg_remove(", 1)[1]

    def test_static_fops_outlive_debugfs(self):
        self.assertIn("static const struct file_operations r800_flexpmu_fops", self.code)
        self.assertIn(".owner = THIS_MODULE", self.code)

    def test_duplicate_probe_rejected(self):
        self.assertIn("if (flexpmu_dbg_info)", self.probe)
        self.assertIn("ret = -EBUSY;", self.probe)

    def test_optional_rtc_bounds(self):
        self.assertIn("resource_size(&rtc_res) >= CURTICCNT_0 + sizeof(u32)", self.probe)

    def test_failed_file_creation_unwinds_before_publication(self):
        self.assertLess(self.probe.index("goto err_remove_files;"),
                        self.probe.index("r800_flexpmu_ready = true;"))
        self.assertLess(self.probe.index("err_remove_files:"),
                        self.probe.index("debugfs_remove_recursive(flexpmu_dbg_root);"))

    def test_remove_drains_readers_before_unmapping(self):
        drain = self.remove.index("debugfs_remove_recursive(flexpmu_dbg_root);")
        self.assertLess(self.remove.index("r800_mif_base = NULL;"), drain)
        self.assertLess(drain, self.remove.index("iounmap(flexpmu_dbg_base);"))

    def test_remove_clears_resources(self):
        self.assertIn("iounmap(rtc_base);", self.remove)
        self.assertIn("flexpmu_dbg_info = NULL;", self.remove)

    def test_debugfs_ready_gate(self):
        self.assertEqual(self.code.count("if (!r800_flexpmu_ready)"), 2)
        self.assertLess(self.remove.index("r800_flexpmu_ready = false;"),
                        self.remove.index("debugfs_remove_recursive"))

    def test_debugfs_input_and_format_bounds(self):
        self.assertIn("if (!count)", self.code)
        self.assertIn("copy_from_user(buf, user_buf, count)", self.code)
        self.assertIn("scnprintf(buf +", self.code)


if __name__ == "__main__":
    unittest.main()
