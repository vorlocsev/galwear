"""Local synthetic factory ZIPs only; no Google binaries."""
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "build"))
from r800_extract_pixel_factory import extract
import r800_verify_pixel_donor as verifier


class PixelDonorManifestTests(unittest.TestCase):
    sha = "a" * 40

    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.archive = self.root / "factory.zip"
        self.out = self.root / "extracted"
        nested = io.BytesIO()
        with zipfile.ZipFile(nested, "w") as inner:
            inner.writestr("system.img", b"\x3a\xff\x26\xed" + bytes(128))
            inner.writestr("vendor.img", bytes(1080) + b"\x53\xef")
            inner.writestr("boot.img", b"ignored")
        with zipfile.ZipFile(self.archive, "w") as outer:
            outer.writestr("image-r11btwifi-rwdc.230905.003.zip", nested.getvalue())
        self.pin = hashlib.sha256(self.archive.read_bytes()).hexdigest()
        extract(self.archive, self.out, self.pin)

    def verify(self):
        with patch.object(verifier, "checkout_sha", return_value=self.sha):
            return verifier.verify(self.archive, self.out, self.sha, self.pin)

    def test_repeat_manifest_matches(self):
        report = self.verify()
        self.assertEqual(report["status"], "PIXEL_FACTORY_REPEAT_EXTRACTION_MATCH")
        self.assertEqual(report["source_sha"], self.sha)
        self.assertEqual(set(report["images"]), {"system.img", "vendor.img"})
        self.assertTrue(report["repeat_extraction_matched"])
        for flag in ("documented_factory_pin_matched", "archive_signature_verified",
                     "avb_verified", "wear_os_runtime_verified", "r800_compatibility_verified",
                     "hardware_tested", "safe_to_flash"):
            self.assertIs(report[flag], False)

    def test_changed_partition_rejected(self):
        (self.out / "system.img").write_bytes(b"tampered")
        with self.assertRaisesRegex(ValueError, "partition digest mismatch"):
            self.verify()

    def test_missing_partition_rejected(self):
        (self.out / "vendor.img").unlink()
        with self.assertRaisesRegex(ValueError, "inventory mismatch"):
            self.verify()

    def test_extra_partition_rejected(self):
        (self.out / "boot.img").write_bytes(b"unexpected")
        with self.assertRaisesRegex(ValueError, "inventory mismatch"):
            self.verify()

    def test_changed_manifest_rejected(self):
        path = self.out / "pixel-evidence.json"
        manifest = json.loads(path.read_text())
        manifest["safe_to_flash"] = True
        path.write_text(json.dumps(manifest))
        with self.assertRaisesRegex(ValueError, "manifest differs"):
            self.verify()

    def test_archive_change_rejected(self):
        with self.archive.open("ab") as stream:
            stream.write(b"changed")
        with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
            self.verify()

    def test_symlink_partition_rejected(self):
        file = self.out / "system.img"
        outside = self.root / "same.img"
        file.rename(outside)
        file.symlink_to(outside)
        with self.assertRaises(ValueError):
            self.verify()

    def test_symlink_manifest_rejected(self):
        file = self.out / "pixel-evidence.json"
        outside = self.root / "same.json"
        file.rename(outside)
        file.symlink_to(outside)
        with self.assertRaisesRegex(ValueError, "Symlink"):
            self.verify()


if __name__ == "__main__":
    unittest.main()
