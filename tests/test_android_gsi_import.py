"""Synthetic GSI import checks; no Google archive download."""
import hashlib
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch
import warnings
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "build"))
import r800_android_gsi_import as a


class GsiTests(unittest.TestCase):
    def test_published_digest_is_pinned(self):
        self.assertEqual(a.ZIP_SHA256, "019b517dad4c3ee475302b4e8e96fe35934968a083c4edfe387611f08e2f71bc")

    def test_wrong_zip_digest_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            archive = root / "donor.zip"
            archive.write_bytes(b"not the official archive")
            with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
                a.import_gsi(archive, root / "out")

    def test_only_system_image_extracted(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            archive = root / "donor.zip"
            with zipfile.ZipFile(archive, "w") as z:
                z.writestr("system.img", b"fixture-system")
                z.writestr("../ignored", b"ignored")
                z.writestr("vbmeta.img", b"ignored")
            image = root / "system.img"
            self.assertEqual(a.unpack_system(archive, image), hashlib.sha256(b"fixture-system").hexdigest())
            self.assertEqual(image.read_bytes(), b"fixture-system")
            self.assertFalse((root / "vbmeta.img").exists())

    def test_duplicate_system_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            archive = root / "donor.zip"
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                with zipfile.ZipFile(archive, "w") as z:
                    z.writestr("system.img", b"one")
                    z.writestr("system.img", b"two")
            with self.assertRaisesRegex(ValueError, "exactly one"):
                a.unpack_system(archive, root / "system.img")

    def test_symlink_member_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            archive = root / "donor.zip"
            with zipfile.ZipFile(archive, "w") as z:
                member = zipfile.ZipInfo("system.img")
                member.create_system = 3
                member.external_attr = (stat.S_IFLNK | 0o777) << 16
                z.writestr(member, "elsewhere")
            with self.assertRaisesRegex(ValueError, "not a regular"):
                a.unpack_system(archive, root / "system.img")

    def test_import_links_archive_and_image_digests(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            archive = root / "donor.zip"
            with zipfile.ZipFile(archive, "w") as z:
                z.writestr("system.img", b"fixture")
            digest = hashlib.sha256(archive.read_bytes()).hexdigest()
            def extract(image, sha, out, readelf):
                self.assertEqual(image.read_bytes(), b"fixture")
                self.assertEqual(sha, hashlib.sha256(b"fixture").hexdigest())
                return {"safe_to_flash": False}
            with patch.object(a, "ZIP_SHA256", digest), patch.object(a, "extract", side_effect=extract):
                result = a.import_gsi(archive, root / "out")
            self.assertEqual(result["official_zip_sha256"], digest)
            self.assertFalse(result["apex_signature_verified"])
            self.assertFalse(result["dynamic_android_linker_tested"])


if __name__ == "__main__":
    unittest.main()
