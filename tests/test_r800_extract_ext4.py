"""Real ext4 fixture generated from synthetic data; no mount or real donor."""
import hashlib
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/"build"))
from r800_extract_ext4 import extract, HCD


@unittest.skipUnless(shutil.which("debugfs") and shutil.which("mkfs.ext4"), "e2fsprogs unavailable")
class Ext4ExtractionTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.tree = self.root/"fixture"
        self.tree.mkdir()
        self.image = self.root/"rootfs.img"
        self.output = self.root/"out"

    def put(self, name, data):
        p = self.tree/name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
        return p

    def make_image(self):
        with self.image.open("wb") as f:
            f.truncate(16*1024**2)
        subprocess.run(["mkfs.ext4", "-q", "-F", "-d", str(self.tree), str(self.image)],
                       check=True, timeout=30)
        return hashlib.sha256(self.image.read_bytes()).hexdigest()

    def test_read_only_tizen_allowlist(self):
        self.put("usr/lib/firmware/"+HCD, b"synthetic HCD")
        self.put("lib/libc-2.24.so", b"synthetic libc")
        self.put("home/user/private.txt", b"excluded")
        sha = self.make_image()
        report = extract(self.image, self.output, "tizen", sha)
        self.assertEqual((self.output/"tizen/libc.so.6").read_bytes(), b"synthetic libc")
        self.assertEqual((self.output/"payload/fw/bt"/HCD).read_bytes(), b"synthetic HCD")
        self.assertFalse((self.output/"home").exists())
        self.assertIn("tizen/libdl.so.2", report["missing_or_ambiguous"])
        self.assertEqual(hashlib.sha256(self.image.read_bytes()).hexdigest(), sha)
        self.assertFalse(report["safe_to_flash"])

    def test_vendor_profile(self):
        self.put("lib/libeffectsconfig.so", b"synthetic library")
        sha = self.make_image()
        report = extract(self.image, self.output, "vendor", sha)
        self.assertEqual(report["files"]["vendor/lib/libeffectsconfig.so"]["status"], "EXTRACTED")
        self.assertTrue(report["missing_or_ambiguous"])

    def test_ambiguous_glibc(self):
        self.put("lib/libc-2.24.so", b"one")
        self.put("usr/lib/libc-2.24.so", b"two")
        sha = self.make_image()
        report = extract(self.image, self.output, "tizen", sha)
        self.assertEqual(report["files"]["tizen/libc.so.6"]["status"], "AMBIGUOUS")
        self.assertFalse((self.output/"tizen/libc.so.6").exists())

    def test_guest_symlink_rejected(self):
        self.put("lib/other", b"synthetic")
        (self.tree/"lib/libc-2.24.so").symlink_to("other")
        sha = self.make_image()
        with self.assertRaisesRegex(ValueError,"regular donor"):
            extract(self.image, self.output, "tizen", sha)
        self.assertFalse(self.output.exists())

    def test_wrong_hash(self):
        self.make_image()
        with self.assertRaisesRegex(ValueError,"SHA-256"):
            extract(self.image, self.output, "tizen", "0"*64)

if __name__=="__main__":
    unittest.main()
