"""Synthetic Samsung archive tests; no device files."""
import hashlib
import io
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"build"))
from r800_extract_samsung import extract

def ext4_fixture():
    raw=bytearray(4096)
    raw[1080:1082]=b"\x53\xef"
    return bytes(raw)

class SamsungTests(unittest.TestCase):
    def setUp(self):
        t=tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        self.root=Path(t.name)
        self.src=self.root/"AP.tar.md5"
        self.out=self.root/"donor"

    def archive(self,files):
        with tarfile.open(self.src,"w") as t:
            for name,raw in files:
                info=tarfile.TarInfo(name)
                info.size=len(raw)
                t.addfile(info,io.BytesIO(raw))
        with self.src.open("ab") as f:
            f.write(b"synthetic MD5 trailer")
        return hashlib.sha256(self.src.read_bytes()).hexdigest()

    def test_j4_allowlist(self):
        sha=self.archive([("vendor.img",ext4_fixture()),("boot.img",b"ignored"),("../../escape",b"ignored")])
        r=extract(self.src,self.out,"j4",sha)
        self.assertEqual(r["images"]["vendor.img"]["format"],"raw_ext4")
        self.assertEqual(set(p.name for p in self.out.iterdir()),{"vendor.img","samsung-evidence.json"})
        self.assertFalse(r["safe_to_flash"])

    def test_r800_allowlist(self):
        sha=self.archive([("rootfs.img",ext4_fixture()),("param.bin",b"assets"),("efs.img",b"ignored")])
        extract(self.src,self.out,"r800",sha)
        self.assertFalse((self.out/"efs.img").exists())

    def test_hash_mismatch(self):
        self.archive([("vendor.img",ext4_fixture())])
        with self.assertRaisesRegex(ValueError,"SHA-256"):
            extract(self.src,self.out,"j4","0"*64)

    def test_duplicate(self):
        sha=self.archive([("vendor.img",ext4_fixture()),("vendor.img",ext4_fixture())])
        with self.assertRaisesRegex(ValueError,"Duplicate"):
            extract(self.src,self.out,"j4",sha)
        self.assertFalse(self.out.exists())

    def test_missing(self):
        sha=self.archive([("system.img",ext4_fixture())])
        with self.assertRaisesRegex(ValueError,"Missing donor"):
            extract(self.src,self.out,"j4",sha)

    def test_wrong_format(self):
        sha=self.archive([("vendor.img",b"not image")])
        with self.assertRaisesRegex(ValueError,"format"):
            extract(self.src,self.out,"j4",sha)

    @unittest.skipUnless(shutil.which("lz4"),"lz4 CLI unavailable")
    def test_lz4(self):
        raw=ext4_fixture()
        encoded=subprocess.run(["lz4","-z","-c"],input=raw,stdout=subprocess.PIPE,check=True).stdout
        sha=self.archive([("vendor.img.lz4",encoded)])
        r=extract(self.src,self.out,"j4",sha)
        self.assertTrue(r["images"]["vendor.img"]["compressed"])
        self.assertEqual((self.out/"vendor.img").read_bytes(),raw)

if __name__=="__main__":
    unittest.main()
