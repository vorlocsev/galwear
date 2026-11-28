"""Stock archive intake tests using real small EXT4 images, not stock firmware."""
import io
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"build"))
import r800_extract_stock_donor as stock
import r800_bind_stock_donor as binding
import r800_partition_identity as identity


class StockDonorTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root=Path(tmp.name)
        self.archive=self.root/"stock.tar.md5"
        self.output=self.root/"out"
        self.image=self.root/"image.img"
        tree=self.root/"tree"
        tree.mkdir()
        (tree/"build.prop").write_text("ro.build.version.sdk=28\nro.build.version.release=9\n")
        subprocess.run(["mke2fs","-q","-t","ext4","-F","-d",str(tree),str(self.image),"8192"],
                       check=True,capture_output=True)

    def pack(self,names):
        with tarfile.open(self.archive,"w") as tar:
            for name,data in names:
                member=tarfile.TarInfo(name)
                member.size=len(data)
                tar.addfile(member,io.BytesIO(data))

    def extract(self,role,pin=None):
        with patch.object(stock,"checkout_sha"),patch.object(identity,"checkout_sha"):
            return stock.extract_stock(self.archive,pin or stock.digest(self.archive)["sha256"],
                                       role,self.output,"a"*40)

    def test_rootfs_selected_only(self):
        raw=self.image.read_bytes()
        self.pack([("rootfs.img",raw),("csa.img",b"ignored"),("../other",b"ignored")])
        r=self.extract("r800-rootfs")
        self.assertEqual(r["partition"]["sha256"],stock.digest(self.image)["sha256"])
        self.assertEqual(set(p.name for p in self.output.iterdir()),{"rootfs.img","stock-donor-evidence.json"})
        self.assertFalse(r["safe_to_flash"])

    def test_j4_vendor_identity(self):
        self.pack([("vendor.img.ext4",self.image.read_bytes())])
        r=self.extract("j4-vendor")
        self.assertEqual(r["filesystem"]["kind"],"EXT4")
        self.assertEqual(r["android_identity"]["filesystem"],r["filesystem"])
        self.assertFalse(r["donor_model_verified"])

    def test_ambiguous_selected_partition(self):
        self.pack([("rootfs.img",b"one"),("rootfs.img.lz4",b"two")])
        with self.assertRaisesRegex(ValueError,"Ambiguous selected"):
            self.extract("r800-rootfs")
        self.assertFalse(self.output.exists())

    def test_wrong_role(self):
        self.pack([("vendor.img",b"vendor")])
        with self.assertRaisesRegex(ValueError,"Selected stock partition missing"):
            self.extract("r800-rootfs")

    def test_wrong_hash(self):
        self.pack([("rootfs.img",self.image.read_bytes())])
        with self.assertRaisesRegex(ValueError,"SHA-256 mismatch"):
            self.extract("r800-rootfs","0"*64)

    def test_invalid_filesystem(self):
        self.pack([("rootfs.img",b"x"*4096)])
        with self.assertRaisesRegex(ValueError,"Unsupported partition filesystem"):
            self.extract("r800-rootfs")

    def test_bad_lz4_magic(self):
        self.pack([("vendor.img.lz4",b"not a compressed frame")])
        with self.assertRaisesRegex(ValueError,"Invalid LZ4 frame magic"):
            self.extract("j4-vendor")

    def test_over_budget_sparse_expansion(self):
        import struct
        header=struct.pack("<I4H4I",0xed26ff3a,1,0,28,12,4096,1048577,1,0)
        self.pack([("vendor.img",header)])
        with self.assertRaisesRegex(ValueError,"Stock sparse expansion exceeds donor budget"):
            self.extract("j4-vendor")

    @unittest.skipUnless(shutil.which("lz4"),"lz4 not available")
    def test_actual_lz4_vendor(self):
        packed=self.root/"vendor.lz4"
        subprocess.run(["lz4","-z",str(self.image),str(packed)],check=True,capture_output=True)
        self.pack([("vendor.img.lz4",packed.read_bytes())])
        r=self.extract("j4-vendor")
        self.assertEqual(r["partition"]["sha256"],stock.digest(self.image)["sha256"])
        self.assertFalse(r["donor_authenticity_verified"])


    def bind(self,build_input="tizen",archive_pin=None,source="a"*40):
        image=self.output/"rootfs.img"
        report=self.output/"stock-donor-evidence.json"
        with patch.object(binding,"checkout_sha"):
            return binding.verify(image,stock.digest(image)["sha256"],report,
                                  stock.digest(report)["sha256"],
                                  archive_pin or stock.digest(self.archive)["sha256"],
                                  build_input,source)

    def test_stock_build_binding(self):
        self.pack([("rootfs.img",self.image.read_bytes())])
        self.extract("r800-rootfs")
        result=self.bind()
        self.assertEqual(result["status"],"STOCK_REPORT_AND_RAW_INPUT_MATCH_ONLY")
        self.assertFalse(result["archive_rehashed"])
        self.assertFalse(result["safe_to_flash"])

    def test_stock_build_binding_wrong_archive_pin(self):
        self.pack([("rootfs.img",self.image.read_bytes())])
        self.extract("r800-rootfs")
        with self.assertRaisesRegex(ValueError,"Stock archive pin"):
            self.bind(archive_pin="0"*64)

    def test_stock_build_binding_wrong_role(self):
        self.pack([("rootfs.img",self.image.read_bytes())])
        self.extract("r800-rootfs")
        with self.assertRaisesRegex(ValueError,"Unexpected stock extraction scope"):
            self.bind(build_input="j4")

    def test_stock_build_binding_stale_report(self):
        self.pack([("rootfs.img",self.image.read_bytes())])
        self.extract("r800-rootfs")
        with self.assertRaisesRegex(ValueError,"Evidence scope mismatch"):
            self.bind(source="b"*40)

    def test_stock_build_binding_rehashed_report_with_wrong_chain(self):
        self.pack([("rootfs.img",self.image.read_bytes())])
        self.extract("r800-rootfs")
        report=self.output/"stock-donor-evidence.json"
        data=json.loads(report.read_bytes())
        data["normalization"]["raw_bytes"]+=1
        report.write_text(json.dumps(data))
        with self.assertRaisesRegex(ValueError,"Stock normalization chain mismatch"):
            self.bind()

    def test_stock_build_binding_rehashed_wrong_image(self):
        self.pack([("rootfs.img",self.image.read_bytes())])
        self.extract("r800-rootfs")
        image=self.output/"rootfs.img"
        image.chmod(0o600)
        with image.open("r+b") as stream:
            stream.write(b"changed")
        with self.assertRaisesRegex(ValueError,"Stock build input bytes mismatch"):
            self.bind()

    def test_stock_build_binding_j4(self):
        self.pack([("vendor.img.ext4",self.image.read_bytes())])
        self.extract("j4-vendor")
        image=self.output/"vendor.img"
        report=self.output/"stock-donor-evidence.json"
        with patch.object(binding,"checkout_sha"):
            result=binding.verify(image,stock.digest(image)["sha256"],report,
                                  stock.digest(report)["sha256"],
                                  stock.digest(self.archive)["sha256"],"j4","a"*40)
        self.assertEqual(result["role"],"j4-vendor")
        self.assertFalse(result["donor_authenticity_verified"])


if __name__=="__main__":
    unittest.main()
