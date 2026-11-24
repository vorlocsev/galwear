"""Synthetic graphics inventory checks. No proprietary binaries or execution."""
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "build"))
import r800_graphics_inventory as inv
from test_android_linker_audit import fixture


class GraphicsInventoryTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.base = Path(tmp.name)
        self.root = self.base / "guest"
        self.root.mkdir()
        self.config = self.base / "config"
        self.config.write_text("".join(f"{k}={v}\n" for k, v in inv.REQUIRED.items()))

    def put(self, path, abi="arm", needed=()):
        dest = self.root / path.lstrip("/")
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(fixture(abi, needed))

    def populate(self, split=False):
        for role in inv.MANDATORY:
            self.put(inv.ROLES[role][0])
        for role in (("mali_egl", "mali_gles1", "mali_gles2") if split else ("mali_monolithic",)):
            self.put(inv.ROLES[role][0])

    def test_monolithic_and_split_driver(self):
        for split in (False, True):
            self.populate(split)
            result = inv.audit(self.root, self.config)
            self.assertEqual(result["status"], "STATIC_GRAPHICS_CANDIDATES_FOUND")
            self.assertFalse(result["gpu_rendering_tested"])
            self.assertFalse(result["safe_to_flash"])
            if not split:
                (self.root / inv.ROLES["mali_monolithic"][0].lstrip("/")).unlink()

    def test_missing_driver_family(self):
        result = inv.audit(self.root, self.config)
        self.assertIn("mali_driver_family", result["missing_roles"])
        self.assertEqual(result["status"], "REVIEW_REQUIRED")

    def test_wrong_architecture(self):
        self.populate()
        self.put(inv.ROLES["gralloc"][0], "arm64")
        result = inv.audit(self.root, self.config)
        self.assertIn("gralloc", result["missing_roles"])
        self.assertTrue(result["errors"])

    def test_missing_dependency_and_sibling_candidate(self):
        self.populate()
        self.put(inv.ROLES["mali_monolithic"][0], needed=("libx.so",))
        self.assertEqual(inv.audit(self.root, self.config)["status"], "REVIEW_REQUIRED")
        self.put("/vendor/lib/egl/libx.so")
        self.assertEqual(inv.audit(self.root, self.config)["status"], "STATIC_GRAPHICS_CANDIDATES_FOUND")

    def test_missing_kernel_option(self):
        self.populate()
        self.config.write_text(self.config.read_text().replace("CONFIG_ION=y\n", ""))
        result = inv.audit(self.root, self.config)
        self.assertIn("CONFIG_ION", result["kernel"]["missing_or_wrong"])
        self.assertEqual(result["status"], "REVIEW_REQUIRED")

    def test_duplicate_kernel_option(self):
        with self.config.open("a") as f:
            f.write("CONFIG_ION=n\n")
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            inv.audit(self.root, self.config)

    def test_output_cannot_be_inside_guest(self):
        with self.assertRaises(SystemExit) as error:
            # main parses process arguments; patch only the invocation.
            from unittest.mock import patch
            with patch.object(sys, "argv", ["audit", "--root", str(self.root),
                              "--config", str(self.config), "--output", str(self.root / "out.json")]):
                inv.main()
        self.assertEqual(error.exception.code, 2)
        self.assertFalse((self.root / "out.json").exists())


if __name__ == "__main__":
    unittest.main()
