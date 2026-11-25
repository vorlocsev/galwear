"""Synthetic virt-only effective Kconfig and embedded archive checks."""
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "build"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import r800_qemu_virt_contract as a
import r800_qemu_system_init as boot
from test_initramfs_recipe import fake_aarch64_elf

LIST = "/scratch/initramfs.list"
CONFIG = "\n".join("CONFIG_" + key + "=y" for key in a.REQUIRED) + '\nCONFIG_INITRAMFS_SOURCE="' + LIST + '"\nCONFIG_CMDLINE=""\n'


class VirtTests(unittest.TestCase):
    def test_required_config(self):
        self.assertFalse(a.inspect(CONFIG, LIST)["safe_to_flash"])

    def test_missing_console(self):
        with self.assertRaisesRegex(ValueError, "Missing virt"):
            a.inspect(CONFIG.replace("CONFIG_SERIAL_AMBA_PL011_CONSOLE=y", ""), LIST)

    def test_forbidden_config(self):
        for name in a.FORBIDDEN:
            with self.subTest(name=name):
                with self.assertRaisesRegex(ValueError, "Unexpected enabled"):
                    a.inspect(CONFIG + "CONFIG_" + name + "=y\n", LIST)

    def test_wrong_list(self):
        with self.assertRaisesRegex(ValueError, "list changed"):
            a.inspect(CONFIG, "/other/initramfs.list")

    def test_exact_embedded_archive(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            init = root / "init"
            init.write_bytes(fake_aarch64_elf())
            archive = root / "archive"
            data = boot.create_archive(init)
            archive.write_bytes(data)
            self.assertEqual(boot.verify_embedded(b"prefix" + data, archive, init)["image_offset"], 6)
            for invalid in (b"prefix", data + data):
                with self.assertRaisesRegex(ValueError, "missing or ambiguous"):
                    boot.verify_embedded(invalid, archive, init)


if __name__ == "__main__":
    unittest.main()
