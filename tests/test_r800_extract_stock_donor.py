"""Stock archive intake tests using real small EXT4 images, not stock firmware."""
import io
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

    @unittest.skipUnless(shutil.which("lz4"),"lz4 not available")
    def test_actual_lz4_vendor(self):
        packed=self.root/"vendor.lz4"
        subprocess.run(["lz4","-z",str(self.image),str(packed)],check=True,capture_output=True)
        self.pack([("vendor.img.lz4",packed.read_bytes())])
        r=self.extract("j4-vendor")
        self.assertEqual(r["partition"]["sha256"],stock.digest(self.image)["sha256"])
        self.assertFalse(r["donor_authenticity_verified"])


if __name__=="__main__":
    unittest.main()
