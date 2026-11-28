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
import r800_bind_pixel_system as binding


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


    def binding_fixture(self):
        self.factory(self.raw)
        with patch.object(intake,"FACTORY_SHA256",self.pin):
            report=self.prepare()
        self.assertTrue(report["documented_factory_pin_matched"])
        return report

    def describe(self,report):
        with patch.object(binding,"FACTORY_SHA256",self.pin):
            return binding.describe(report,hashlib.sha256(self.raw).hexdigest(),
                                    "b"*64,self.source)

    def test_pixel_binding_direct(self):
        report=self.binding_fixture()
        path=self.output/"raw-donor-evidence.json"
        with patch.object(binding,"FACTORY_SHA256",self.pin),patch.object(binding,"checkout_sha"):
            result=binding.verify(self.output/"system.img",hashlib.sha256(self.raw).hexdigest(),
                                  path,hashlib.sha256(path.read_bytes()).hexdigest(),self.source)
        self.assertEqual(result["status"],"PIXEL_REPORT_AND_RAW_SYSTEM_MATCH_ONLY")
        self.assertFalse(result["archive_rehashed"])
        self.assertFalse(result["safe_to_flash"])

    def test_pixel_binding_unpinned_factory(self):
        report=self.binding_fixture()
        with self.assertRaisesRegex(ValueError,"Expected pinned RWDC"):
            binding.describe(report,hashlib.sha256(self.raw).hexdigest(),"b"*64,self.source)

    def test_pixel_binding_changed_normalization(self):
        report=self.binding_fixture()
        report["partitions"]["system"]["provenance"]["source_bytes"]+=1
        with self.assertRaisesRegex(ValueError,"Pixel normalization source mismatch"):
            self.describe(report)

    def test_pixel_binding_wrong_identity(self):
        report=self.binding_fixture()
        report["partitions"]["system"]["identity"]["image_sha256"]="0"*64
        with self.assertRaisesRegex(ValueError,"Pixel partition identity mismatch"):
            self.describe(report)

    def test_pixel_binding_rejects_erofs(self):
        report=self.binding_fixture()
        report["partitions"]["system"]["filesystem"]["kind"]="EROFS"
        with self.assertRaisesRegex(ValueError,"requires EXT4"):
            self.describe(report)

    def super_fixture(self):
        # Exercise the report chain, not logical extent extraction itself.
        report=self.binding_fixture()
        row=report["partitions"].pop("system")
        report["partitions"]["system_a"]=row
        row["file"]="system_a.img"
        row["identity"]["partition"]="system_a"
        row["provenance"]={"source":"super.img","metadata_slot":0,
                           "raw_bytes":row["bytes"],"raw_sha256":row["sha256"]}
        origin={"bytes":row["bytes"]+4096,"sha256":"c"*64}
        report["factory_extraction"]["images"]={"super.img":{**origin,"format":"unknown_or_container"}}
        report.update(mode="super",metadata_slot=0,
                      super_extraction={"schema":"galwear-r800-super-extraction-v1",
                        "status":"SUPER_SELECTED_PARTITIONS_EXTRACTED_ONLY","source_sha":self.source,
                        "metadata_slot":0,"metadata_sha256":"d"*64,
                        "input":{"format":"raw","source_sha256":origin["sha256"],
                                 "source_bytes":origin["bytes"],"raw_sha256":origin["sha256"],
                                 "raw_bytes":origin["bytes"]},
                        "partitions":{"system_a":{k:row[k] for k in ("file","bytes","sha256")}},
                        **{k:False for k in ("all_slots_verified","filesystem_contents_verified",
                            "avb_verified","wear_os_runtime_verified","hardware_tested","safe_to_flash")}})
        return report

    def test_pixel_binding_super_chain(self):
        result=self.describe(self.super_fixture())
        self.assertEqual(result["partition"],"system_a")
        self.assertEqual(result["metadata_slot"],0)

    def test_pixel_binding_super_slot_mismatch(self):
        report=self.super_fixture()
        report["metadata_slot"]=1
        with self.assertRaisesRegex(ValueError,"Pixel super slot mismatch"):
            self.describe(report)

    def test_pixel_binding_super_changed_partition(self):
        report=self.super_fixture()
        report["super_extraction"]["partitions"]["system_a"]["sha256"]="f"*64
        with self.assertRaisesRegex(ValueError,"Pixel logical partition chain mismatch"):
            self.describe(report)


if __name__=="__main__":
    unittest.main()
