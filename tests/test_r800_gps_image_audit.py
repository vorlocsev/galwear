"""Real ext4 fixtures, no mounting or guest execution."""
import hashlib
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"build"))
from r800_gps_image_audit import check_image
import test_r800_tizen_gnss_preflight as preflight
from test_android_linker_audit import classified_symbol_fixture


@unittest.skipUnless(shutil.which("debugfs") and shutil.which("mkfs.ext4"),
                     "e2fsprogs unavailable")
class GnssImageTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root=Path(temp.name)
        self.tree=self.root/"tree"
        self.image=self.root/"rootfs.img"
        self.put("usr/bin/gpsd",preflight.GnssPreflightTests.bridge_fixture(name=b"daemon"))
        self.put("usr/bin/lhd",preflight.GnssPreflightTests.bridge_fixture(name=b"daemon"))
        self.put("usr/lib/libbrcm.so",preflight.GnssPreflightTests.bridge_fixture())
        self.put("opt/usr/r800dev/gps.last",b"excluded synthetic data")

    def put(self,path,data):
        p=self.tree/path
        p.parent.mkdir(parents=True,exist_ok=True)
        p.write_bytes(data)
        return p

    def make_image(self):
        with self.image.open("wb") as f:
            f.truncate(16*1024**2)
        subprocess.run(["mkfs.ext4","-q","-F","-d",str(self.tree),str(self.image)],
                       check=True,timeout=30)
        return hashlib.sha256(self.image.read_bytes()).hexdigest()

    def inspect(self):
        digest=self.make_image()
        r=check_image(self.image,digest)
        self.assertEqual(hashlib.sha256(self.image.read_bytes()).hexdigest(),digest)
        self.assertFalse(r["safe_to_flash"])
        self.assertFalse(r["runtime_paths_verified"])
        self.assertNotIn("gps.last",str(r))
        return r

    def test_complete(self):
        r=self.inspect()
        self.assertEqual(r["status"],"STATIC_IMAGE_GNSS_CLOSURE_ONLY",r["problems"])
        self.assertEqual(len(r["extracted_elf"]),3)

    def test_symlink_dependency(self):
        data=classified_symbol_fixture("arm",version_kind="need")
        struct.pack_into("<I",data,36,0x05000200)
        self.put("usr/bin/gpsd",data)
        lib=classified_symbol_fixture("arm",section=1,version_kind="define")
        struct.pack_into("<I",lib,36,0x05000200)
        self.put("usr/lib/libx-real.so",lib)
        (self.tree/"usr/lib/libx.so").symlink_to("libx-real.so")
        (self.tree/"lib").symlink_to("/usr/lib")
        r=self.inspect()
        self.assertEqual(r["status"],"STATIC_IMAGE_GNSS_CLOSURE_ONLY",r["problems"])
        self.assertEqual(r["dependency_evidence"]["aliases"]["/lib/libx.so"],
                         "/usr/lib/libx-real.so")
        self.assertIn("/usr/lib/libx-real.so",r["extracted_elf"])

    def test_missing_daemon(self):
        (self.tree/"usr/bin/lhd").unlink()
        self.assertIn("DEPENDENCY_CLOSURE_REVIEW",self.inspect()["problems"])

    def test_missing_export(self):
        self.put("usr/lib/libbrcm.so",preflight.GnssPreflightTests.bridge_fixture(name=b"wrong"))
        self.assertIn("BRIDGE_EXPORT_NOT_CONFIRMED",self.inspect()["problems"])

    def test_escape_link(self):
        p=self.tree/"usr/lib/libbrcm.so"
        p.unlink()
        p.symlink_to("../../../../etc/passwd")
        self.assertIn("BRIDGE_LIBRARY_REJECTED",self.inspect()["problems"])

    def test_wrong_hash(self):
        self.make_image()
        with self.assertRaisesRegex(ValueError,"SHA-256"):
            check_image(self.image,"0"*64)


if __name__=="__main__":
    unittest.main()
