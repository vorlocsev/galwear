"""Synthetic archives only; no Google firmware downloaded."""
import hashlib
import io
from pathlib import Path
import sys
import tempfile
import unittest
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "build"))
from r800_extract_pixel_factory import extract


class PixelExtractionTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.archive = self.root / "factory.zip"
        self.out = self.root / "out"

    def make(self, system=True, nested_name="image-r11btwifi-rwdc.230905.003.zip"):
        nested = io.BytesIO()
        with zipfile.ZipFile(nested, "w") as inner:
            if system:
                inner.writestr("system.img", b"\x3a\xff\x26\xed" + bytes(128))
            inner.writestr("boot.img", b"ignored")
            inner.writestr("../../escape", b"ignored")
        with zipfile.ZipFile(self.archive, "w") as outer:
            outer.writestr(nested_name, nested.getvalue())
        return hashlib.sha256(self.archive.read_bytes()).hexdigest()

    def test_allowlist(self):
        sha = self.make()
        result = extract(self.archive, self.out, sha)
        self.assertEqual(result["images"]["system.img"]["format"], "android_sparse")
        self.assertEqual(set(p.name for p in self.out.iterdir()), {"system.img", "pixel-evidence.json"})
        self.assertFalse(result["safe_to_flash"])

    def test_wrong_hash(self):
        self.make()
        with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
            extract(self.archive, self.out, "0"*64)
        self.assertFalse(self.out.exists())

    def test_wrong_model(self):
        sha = self.make(nested_name="image-r11-rwdc.230905.003.zip")
        with self.assertRaisesRegex(ValueError, "Bluetooth/Wi-Fi"):
            extract(self.archive, self.out, sha)

    def test_missing_system(self):
        sha = self.make(system=False)
        with self.assertRaisesRegex(ValueError, "No system or super"):
            extract(self.archive, self.out, sha)

    def test_no_overwrite(self):
        sha = self.make()
        self.out.mkdir()
        with self.assertRaisesRegex(ValueError, "already exists"):
            extract(self.archive, self.out, sha)


if __name__ == "__main__":
    unittest.main()
