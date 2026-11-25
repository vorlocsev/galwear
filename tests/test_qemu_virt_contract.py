"""Synthetic virt-only effective Kconfig and embedded archive checks."""
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "build"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import r800_qemu_virt_contract as a
import r800_qemu_system_init as boot
from test_initramfs_recipe import fake_aarch64_elf

LIST = "/scratch/initramfs.list"
CONFIG = "\n".join("CONFIG_" + key + "=y" for key in a.REQUIRED) + '\nCONFIG_INITRAMFS_SOURCE="' + LIST + '"\nCONFIG_CMDLINE=""\nCONFIG_NR_CPUS=2\nCONFIG_ANDROID_BINDER_DEVICES="binder,hwbinder,vndbinder"\n'

PROPERTY_CONFIG = CONFIG + "\n".join("CONFIG_" + key + "=y" for key in a.PROPERTY_REQUIRED) + '\nCONFIG_DEFAULT_SECURITY="selinux"\n'


class VirtTests(unittest.TestCase):
    def test_required_config(self):
        self.assertFalse(a.inspect(CONFIG, LIST)["safe_to_flash"])

    def test_property_config(self):
        report = a.inspect(PROPERTY_CONFIG, LIST, "property")
        self.assertEqual(report["profile"], "property")
        self.assertFalse(report["selinux_policy_loaded"])
        self.assertFalse(report["property_service_started"])

    def test_property_cannot_satisfy_minimal(self):
        with self.assertRaisesRegex(ValueError, "CONFIG_NET"):
            a.inspect(PROPERTY_CONFIG, LIST)

    def test_property_dependencies_required(self):
        for key in a.PROPERTY_REQUIRED:
            with self.subTest(key=key):
                with self.assertRaisesRegex(ValueError, "Missing virt built-in CONFIG_" + key):
                    a.inspect(PROPERTY_CONFIG.replace("CONFIG_" + key + "=y\n", ""), LIST, "property")

    def test_property_forbidden_features(self):
        for key in a.PROPERTY_FORBIDDEN:
            with self.subTest(key=key):
                with self.assertRaisesRegex(ValueError, "Unexpected enabled CONFIG_" + key):
                    a.inspect(PROPERTY_CONFIG + "CONFIG_" + key + "=y\n", LIST, "property")

    def test_property_default_security(self):
        with self.assertRaisesRegex(ValueError, "Expected SELinux"):
            a.inspect(PROPERTY_CONFIG.replace('CONFIG_DEFAULT_SECURITY="selinux"', 'CONFIG_DEFAULT_SECURITY=""'), LIST, "property")

    def test_block_profile(self):
        cfg = PROPERTY_CONFIG + "\n".join("CONFIG_" + key + "=y" for key in a.BLOCK_REQUIRED) + "\n"
        self.assertTrue(a.inspect(cfg, LIST, "block")["virtio_block_profile"])
        with self.assertRaisesRegex(ValueError, "CONFIG_VIRTIO_BLK|CONFIG_VIRTIO_MMIO"):
            a.inspect(cfg, LIST, "property")
        for key in a.BLOCK_REQUIRED:
            with self.subTest(key=key):
                with self.assertRaisesRegex(ValueError, "Missing virt built-in"):
                    a.inspect(cfg.replace("CONFIG_" + key + "=y\n", ""), LIST, "block")
        for key in a.BLOCK_FORBIDDEN:
            with self.subTest(key=key):
                with self.assertRaisesRegex(ValueError, "Unexpected enabled"):
                    a.inspect(cfg + "CONFIG_" + key + "=y\n", LIST, "block")

    def test_invalid_profile(self):
        with self.assertRaisesRegex(ValueError, "Unknown virt profile"):
            a.inspect(CONFIG, LIST, "hardware")

    def test_wrong_binder_devices(self):
        with self.assertRaisesRegex(ValueError, "Binder device list"):
            a.inspect(CONFIG.replace("binder,hwbinder,vndbinder", "binder"), LIST)

    def test_wrong_cpu_capacity(self):
        with self.assertRaisesRegex(ValueError, "two CPUs"):
            a.inspect(CONFIG.replace("CONFIG_NR_CPUS=2", "CONFIG_NR_CPUS=1"), LIST)

    def test_missing_smp(self):
        with self.assertRaisesRegex(ValueError, "CONFIG_SMP"):
            a.inspect(CONFIG.replace("CONFIG_SMP=y", "# CONFIG_SMP is not set"), LIST)

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

    def test_archive_changed_after_audit_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            init = root / "init"
            init.write_bytes(fake_aarch64_elf())
            archive = root / "archive"
            data = boot.create_archive(init)
            archive.write_bytes(data)
            original_audit = boot.inspect_cpio

            def mutate_after_audit(path, binary):
                report = original_audit(path, binary)
                path.write_bytes(data + bytes(4))
                return report

            with patch.object(boot, "inspect_cpio", side_effect=mutate_after_audit):
                with self.assertRaisesRegex(ValueError, "changed after audit"):
                    boot.verify_embedded(b"prefix" + data + bytes(4), archive, init)

    def test_compile_evidence_must_be_json_object(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            init = root / "init"
            init.write_bytes(fake_aarch64_elf())
            evidence = root / "report.json"
            evidence.write_text("[]")
            with self.assertRaisesRegex(ValueError, "Init does not match"):
                boot.run(init, evidence, root / "Image", root / "out")

    def test_oversized_compile_evidence_refused(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            init = root / "init"
            init.write_bytes(fake_aarch64_elf())
            evidence = root / "report.json"
            evidence.write_bytes(b" " * 65537)
            with self.assertRaisesRegex(ValueError, "too large"):
                boot.run(init, evidence, root / "Image", root / "out")


if __name__ == "__main__":
    unittest.main()
