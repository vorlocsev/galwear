"""Synthetic factory ZIPs with actual EXT4 donor fixtures; not Wear OS."""
import hashlib
import io
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile
import zlib

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"build"))
import r800_prepare_pixel_raw_donor as intake
import r800_partition_identity as identity


class PixelRawDonorTests(unittest.TestCase):
    source="a"*40

    def setUp(self):
        tmp=tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root=Path(tmp.name)
        self.archive=self.root/"factory.zip"
        self.output=self.root/"raw"
        tree=self.root/"system"
        tree.mkdir()
        (tree/"build.prop").write_text("ro.build.version.sdk=30\nro.build.version.release=11\nro.product.cpu.abi=armeabi-v7a\n")
        image=self.root/"system.img"
        subprocess.run(["mke2fs","-q","-F","-t","ext4","-b","4096","-d",str(tree),str(image),"2048"],
                       check=True,capture_output=True)
        self.raw=image.read_bytes()

    def factory(self, image):
        nested=io.BytesIO()
        with zipfile.ZipFile(nested,"w",compression=zipfile.ZIP_DEFLATED) as z:
            z.writestr("system.img",image)
            z.writestr("boot.img",b"ignored")
        with zipfile.ZipFile(self.archive,"w") as z:
            z.writestr("image-r11btwifi-rwdc.230905.003.zip",nested.getvalue())
        self.pin=hashlib.sha256(self.archive.read_bytes()).hexdigest()

    def prepare(self, mode="direct", names=("system",), slot=None, pin=None):
        with patch.object(intake,"checkout_sha"),patch.object(identity,"checkout_sha"):
            return intake.prepare(self.archive,self.output,self.source,mode,names,slot,
                                  expected=self.pin if pin is None else pin)

    def test_raw_ext4(self):
        self.factory(self.raw)
        report=self.prepare()
        self.assertEqual(report["status"],"SELECTED_PIXEL_RAW_DONOR_PARTITIONS_ONLY")
        self.assertEqual((self.output/"system.img").read_bytes(),self.raw)
        self.assertTrue(report["partitions"]["system"]["identity"]["properties"]["literal_android_11_hint"])
        self.assertFalse(report["documented_factory_pin_matched"])
        self.assertFalse(report["safe_to_flash"])
        self.assertFalse((self.output/"boot.img").exists())

    def test_sparse_ext4(self):
        length=len(self.raw)
        sparse=struct.pack("<I4H4I",0xed26ff3a,1,0,28,12,4096,length//4096,1,zlib.crc32(self.raw))
        sparse+=struct.pack("<HHII",0xcac1,0,length//4096,length+12)+self.raw
        self.factory(sparse)
        report=self.prepare()
        self.assertEqual(report["partitions"]["system"]["provenance"]["format"],"android_sparse_v1")
        self.assertEqual((self.output/"system.img").read_bytes(),self.raw)

    def test_wrong_archive_pin(self):
        self.factory(self.raw)
        with self.assertRaisesRegex(ValueError,"SHA-256 mismatch"):
            self.prepare(pin="0"*64)
        self.assertFalse(self.output.exists())

    def test_missing_vendor(self):
        self.factory(self.raw)
        with self.assertRaisesRegex(ValueError,"direct factory image absent"):
            self.prepare(names=("system","vendor"))

    def test_slot_mismatch(self):
        self.factory(self.raw)
        with self.assertRaisesRegex(ValueError,"explicit slot"):
            self.prepare(mode="super",names=("system_b",),slot=0)

    def test_invalid_filesystem(self):
        self.factory(bytes(4096))
        with self.assertRaisesRegex(ValueError,"Unsupported partition filesystem"):
            self.prepare()
        self.assertFalse(self.output.exists())


if __name__=="__main__":
    unittest.main()
