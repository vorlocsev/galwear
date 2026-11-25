"""Synthetic init and property-service build inventory checks."""
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "build"))
import r800_android_init_inventory as a


class InitInventoryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / "system/bin/bootstrap").mkdir(parents=True)
        for name in a.MODULES.values():
            (self.root / "system/bin" / name).write_bytes(b"fixture")

    def test_inventory_is_static_only(self):
        elf = {"elf_type": 3, "interpreter": "/system/bin/linker64",
               "needed": ["libc.so", "libdl.so"], "sha256": "a" * 64}
        with patch.object(a, "inspect_elf", return_value=elf):
            report = a.inventory(self.root, "readelf")
        self.assertEqual(set(report["modules"]), set(a.MODULES))
        self.assertEqual(report["direct_dependencies"], ["libc.so", "libdl.so"])
        for key in ("dependency_closure_verified", "android_init_started",
                    "property_service_started", "socket_transaction_tested",
                    "android_sepolicy_tested", "safe_to_flash"):
            self.assertFalse(report[key])

    def test_missing_module(self):
        (self.root / "system/bin/init").unlink()
        with self.assertRaisesRegex(ValueError, "Missing"):
            a.find_binary(self.root, "init")

    def test_ambiguous_bootstrap(self):
        (self.root / "system/bin/bootstrap/init").write_bytes(b"other")
        with self.assertRaisesRegex(ValueError, "ambiguous"):
            a.find_binary(self.root, "init")

    def test_symlinked_module(self):
        path = self.root / "system/bin/init"
        path.unlink()
        path.symlink_to("galwear_property_client")
        with self.assertRaisesRegex(ValueError, "symlinked"):
            a.find_binary(self.root, "init")

    def test_wrong_interpreter(self):
        with patch.object(a, "inspect_elf", return_value={
                "elf_type": 3, "interpreter": "/lib/ld-linux-aarch64.so.1",
                "needed": ["libc.so"]}):
            with self.assertRaisesRegex(ValueError, "Unexpected Android"):
                a.inventory(self.root, "readelf")


if __name__ == "__main__":
    unittest.main()
