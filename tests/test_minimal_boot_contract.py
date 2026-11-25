"""Synthetic effective Kconfig checks for the minimal boot contract."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "build"))
import r800_minimal_boot_contract as a

CONFIG = "\n".join(k + "=y" for k in a.REQUIRED) + '\nCONFIG_INITRAMFS_SOURCE="/scratch/initramfs.list"\nCONFIG_CMDLINE=""\n# CONFIG_CMDLINE_FORCE is not set\n'


class BootContractTests(unittest.TestCase):
    def test_minimal_config(self):
        self.assertTrue(a.audit_config(CONFIG)["builtin_cmdline_empty"])

    def test_force_refused(self):
        with self.assertRaisesRegex(ValueError, "override"):
            a.audit_config(CONFIG.replace("# CONFIG_CMDLINE_FORCE is not set", "CONFIG_CMDLINE_FORCE=y"))

    def test_extend_refused(self):
        with self.assertRaisesRegex(ValueError, "override"):
            a.audit_config(CONFIG + "CONFIG_CMDLINE_EXTEND=y\n")

    def test_nonempty_cmdline_refused(self):
        with self.assertRaisesRegex(ValueError, "command line"):
            a.audit_config(CONFIG.replace('CONFIG_CMDLINE=""', 'CONFIG_CMDLINE="init=/bin/sh"'))

    def test_missing_initramfs_refused(self):
        with self.assertRaisesRegex(ValueError, "initramfs"):
            a.audit_config(CONFIG.replace('/scratch/initramfs.list', ''))

    def test_missing_builtin_refused(self):
        for option in a.REQUIRED:
            with self.subTest(option=option):
                with self.assertRaisesRegex(ValueError, "built-in"):
                    a.audit_config(CONFIG.replace(option + "=y", "# " + option + " is not set"))

    def test_duplicate_option_refused(self):
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            a.audit_config(CONFIG + "CONFIG_CMDLINE_FORCE=y\n")


if __name__ == "__main__":
    unittest.main()
