"""Synthetic vendor input checks: no mounts, firmware or hardware."""
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "build"))
import r800_vendor_inputs as vendor
from test_android_linker_audit import fixture


class VendorInputTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.base = self.root / "base.img"
        self.j4 = self.root / "j4.img"
        self.overlay = self.root / "overlay"
        self.effects = self.root / "libeffectsconfig.so"
        raw = bytearray(2048)
        raw[1080:1082] = b"\x53\xef"
        self.base.write_bytes(raw)
        self.j4.write_bytes(raw)
        for name in vendor.OVERLAY:
            p = self.overlay / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(fixture("arm") if name.endswith(".so") else b"synthetic\n")
        self.effects.write_bytes(fixture("arm"))

    def audit(self):
        return vendor.audit(self.base, self.j4, self.overlay, self.effects)

    def test_input_evidence(self):
        report = self.audit()
        self.assertEqual(report["status"], "VENDOR_INPUT_STRUCTURE_ONLY")
        self.assertEqual(report["base_vendor"]["bytes"], 2048)
        self.assertEqual(len(report["j4_vendor"]["sha256"]), 64)
        self.assertEqual(report["overlay"]["lights.r800.so"]["abi"], "arm")
        self.assertFalse(report["safe_to_flash"])

    def test_invalid_donor_magic(self):
        self.j4.write_bytes(bytes(2048))
        with self.assertRaisesRegex(ValueError, "raw ext4"):
            self.audit()

    def test_wrong_effects_abi(self):
        self.effects.write_bytes(fixture("arm64"))
        with self.assertRaisesRegex(ValueError, "ARM32"):
            self.audit()

    def test_missing_overlay(self):
        (self.overlay / "ueventd.rc").unlink()
        with self.assertRaises(FileNotFoundError):
            self.audit()

    def test_symlinked_overlay(self):
        p = self.overlay / "ueventd.rc"
        p.unlink()
        p.symlink_to(self.effects)
        with self.assertRaisesRegex(ValueError, "Symlink"):
            self.audit()

    def test_changed_input_digest(self):
        first = self.audit()
        self.base.write_bytes(self.base.read_bytes() + b"changed")
        self.assertNotEqual(first, self.audit())


if __name__ == "__main__":
    unittest.main()
