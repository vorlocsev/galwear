"""Real ext4 fixture generated from synthetic data; no mount or real donor."""
import hashlib
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/"build"))
from r800_extract_ext4 import extract, HCD
import r800_extract_ext4 as extractor


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

    def test_gps_glibc_profile_includes_loader(self):
        for name in ("libc", "libdl", "libpthread", "ld"):
            self.put("lib/"+name+"-2.24.so", name.encode("ascii"))
        self.put("home/user/private.txt", b"excluded")
        sha = self.make_image()
        result = extract(self.image, self.output, "gps-glibc", sha)
        self.assertEqual(result["missing_or_ambiguous"], [])
        self.assertEqual((self.output/"tizen/ld-linux.so.3").read_bytes(),b"ld")
        self.assertFalse((self.output/"home").exists())
        self.assertFalse(result["safe_to_flash"])

    def test_gps_gnss_profile_includes_broadcom(self):
        for name in ("libc", "libdl", "libpthread", "ld"):
            self.put("lib/"+name+"-2.24.so", name.encode("ascii"))
        self.put("usr/lib/libbrcm.so", b"synthetic Broadcom")
        self.put("opt/usr/r800dev/gps.last", b"excluded")
        sha = self.make_image()
        result = extract(self.image, self.output, "gps-gnss", sha)
        self.assertEqual(result["missing_or_ambiguous"], [])
        record = result["files"]["tizen/libbrcm.so"]
        self.assertEqual(record["source"], "/usr/lib/libbrcm.so")
        self.assertEqual(record["sha256"], hashlib.sha256(b"synthetic Broadcom").hexdigest())
        self.assertEqual((self.output/"tizen/libbrcm.so").read_bytes(), b"synthetic Broadcom")
        self.assertFalse((self.output/"opt").exists())
        self.assertFalse(result["donor_compatibility_verified"])
        self.assertFalse(result["safe_to_flash"])
        self.assertEqual(hashlib.sha256(self.image.read_bytes()).hexdigest(), sha)

    def test_gps_gnss_missing_broadcom(self):
        for name in ("libc", "libdl", "libpthread", "ld"):
            self.put("lib/"+name+"-2.24.so", name.encode("ascii"))
        sha = self.make_image()
        result = extract(self.image, self.output, "gps-gnss", sha)
        self.assertEqual(result["missing_or_ambiguous"], ["tizen/libbrcm.so"])

    def test_gps_gnss_rejects_broadcom_symlink(self):
        self.put("usr/lib/libbrcm-real.so", b"synthetic Broadcom")
        (self.tree/"usr/lib/libbrcm.so").symlink_to("libbrcm-real.so")
        sha = self.make_image()
        with self.assertRaisesRegex(ValueError, "regular donor"):
            extract(self.image, self.output, "gps-gnss", sha)
        self.assertFalse(self.output.exists())

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

    def test_debugfs_uses_verified_private_snapshot(self):
        self.put("lib/libc-2.24.so", b"synthetic libc")
        sha = self.make_image()
        real_command = extractor.command
        paths = set()

        def observe(tool, image, request, cwd=None):
            self.assertNotEqual(image, self.image)
            self.assertEqual(hashlib.sha256(image.read_bytes()).hexdigest(), sha)
            paths.add(image)
            return real_command(tool, image, request, cwd=cwd)

        with mock.patch.object(extractor, "command", side_effect=observe):
            result = extract(self.image, self.output, "tizen", sha)
        self.assertEqual(len(paths), 1)
        self.assertFalse(next(iter(paths)).exists())
        self.assertTrue(result["snapshot_verified"])
        self.assertEqual((self.output/"tizen/libc.so.6").read_bytes(), b"synthetic libc")

    def test_donor_changed_after_snapshot_rejected(self):
        self.put("lib/libc-2.24.so", b"synthetic libc")
        sha = self.make_image()
        real_command = extractor.command
        changed = False

        def mutate(tool, image, request, cwd=None):
            nonlocal changed
            if not changed:
                with self.image.open("r+b") as stream:
                    stream.seek(0)
                    stream.write(b"changed")
                changed = True
            return real_command(tool, image, request, cwd=cwd)

        with mock.patch.object(extractor, "command", side_effect=mutate):
            with self.assertRaisesRegex(ValueError, "Donor image changed"):
                extract(self.image, self.output, "tizen", sha)
        self.assertTrue(changed)
        self.assertFalse(self.output.exists())

    def test_donor_symlink_rejected(self):
        sha = self.make_image()
        link = self.root/"donor-link.img"
        link.symlink_to(self.image)
        with self.assertRaisesRegex(ValueError, "regular donor image"):
            extract(link, self.output, "tizen", sha)
        self.assertFalse(self.output.exists())

if __name__=="__main__":
    unittest.main()
