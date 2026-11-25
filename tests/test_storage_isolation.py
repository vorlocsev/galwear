"""Synthetic storage isolation configuration checks."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "build"))
import r800_storage_isolation as a

CONFIG = "\n".join(k + "=y" for k in a.RETAIN + a.BASELINE_ENABLED) + '\nCONFIG_INITRAMFS_SOURCE="/scratch/initramfs.list"\nCONFIG_MMC_DW_EXYNOS=y\nCONFIG_USB_STORAGE=m\nCONFIG_BLOCK=y\nCONFIG_SND_SOC_SAMSUNG_ABOX=y\n'


class IsolationTests(unittest.TestCase):
    def test_prepare_disables_selected_storage_paths(self):
        result = a.prepare(CONFIG)
        report = a.verify(result)
        self.assertEqual(report["status"], "STATIC_SELECTED_STORAGE_DRIVERS_DISABLED")
        self.assertFalse(report["storage_write_impossible_proven"])
        self.assertFalse(report["safe_to_flash"])
        self.assertIn("CONFIG_SND_SOC_SAMSUNG_ABOX=y", result)
        self.assertIn("CONFIG_BLOCK=y", result)
        self.assertIn("# CONFIG_USB_STORAGE is not set", result)

    def test_olddefconfig_reenabled_driver_refused(self):
        result = a.prepare(CONFIG)
        for key in ("CONFIG_MMC", "CONFIG_SCSI", "CONFIG_MODULES", "CONFIG_PSTORE"):
            with self.subTest(key=key):
                with self.assertRaisesRegex(ValueError, "still enabled"):
                    a.verify(result.replace("# " + key + " is not set", key + "=y"))

    def test_module_refused(self):
        with self.assertRaisesRegex(ValueError, "still enabled"):
            a.verify(a.prepare(CONFIG) + "CONFIG_MTD=m\n")

    def test_missing_dependency_symbols_allowed(self):
        result = "\n".join(line for line in a.prepare(CONFIG).splitlines()
                           if not line.startswith("# CONFIG_"))
        self.assertTrue(a.verify(result)["checked_disabled_symbols"])

    def test_requires_embedded_init(self):
        with self.assertRaisesRegex(ValueError, "embedded initramfs"):
            a.prepare(CONFIG.replace('"/scratch/initramfs.list"', '""'))

    def test_requires_builtin_console(self):
        with self.assertRaisesRegex(ValueError, "required built-in"):
            a.prepare(CONFIG.replace("CONFIG_SERIAL_SAMSUNG_CONSOLE=y", "CONFIG_SERIAL_SAMSUNG_CONSOLE=m"))

    def test_duplicate_refused(self):
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            a.prepare(CONFIG + "CONFIG_MMC=n\n")

    def test_unexpected_baseline_refused(self):
        with self.assertRaisesRegex(ValueError, "baseline"):
            a.prepare(CONFIG.replace("CONFIG_MMC=y", "# CONFIG_MMC is not set"))


if __name__ == "__main__":
    unittest.main()
