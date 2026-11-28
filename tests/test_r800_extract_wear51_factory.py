"""Synthetic exact-build factory intake tests, no proprietary bytes."""
import hashlib
import io
from pathlib import Path
import tempfile
import unittest
import warnings
import zipfile
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"build"))
import r800_extract_wear51_factory as intake


class Wear51FactoryTests(unittest.TestCase):
    def make(self,root,name=None,duplicate=False):
        inner=io.BytesIO()
        with zipfile.ZipFile(inner,"w") as z:
            z.writestr("system.img",b"\x3a\xff\x26\xed"+b"\0"*2048)
            z.writestr("boot.img",b"ANDROID!"+b"\0"*2048)
            if duplicate:
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore")
                    z.writestr("system.img",b"duplicate")
        archive=root/"factory.zip"
        with zipfile.ZipFile(archive,"w") as z:
            z.writestr(name or "r11btwifi-bw1a.251005.003.w1/image-r11btwifi-bw1a.251005.003.w1.zip",inner.getvalue())
        return archive,hashlib.sha256(archive.read_bytes()).hexdigest()

    def test_exact_build(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            archive,pin=self.make(root)
            r=intake.extract(archive,root/"out",pin)
            self.assertEqual(r["images"]["system.img"]["format"],"android_sparse")
            self.assertEqual(r["images"]["boot.img"]["format"],"android_boot_container")
            self.assertEqual(r["api_catalog_target"],35)
            self.assertFalse(r["safe_to_flash"])

    def test_wrong_build(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            archive,pin=self.make(root,"image-r11btwifi-rwdc.230905.003.zip")
            with self.assertRaisesRegex(ValueError,"exact-build"):
                intake.extract(archive,root/"out",pin)

    def test_duplicate(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            archive,pin=self.make(root,duplicate=True)
            with self.assertRaisesRegex(ValueError,"Duplicate"):
                intake.extract(archive,root/"out",pin)

    def test_wrong_pin(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            archive,pin=self.make(root)
            with self.assertRaisesRegex(ValueError,"pinned"):
                intake.extract(archive,root/"out","0"*64)

if __name__=="__main__":
    unittest.main()
