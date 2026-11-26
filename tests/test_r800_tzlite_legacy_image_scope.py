"""Real ext4 legacy scope inventory and strict directory parser."""
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"build"))
import r800_tzlite_legacy_image_scope as scope
from r800_tzlite_legacy_scope import inspect

DOTS="/2/040755/0/0/.//\n/2/040755/0/0/..//\n"
FILE="/12/100644/1000/1000/plugin.so/4/\n"


class DirectoryParserTests(unittest.TestCase):
    def test_regular_listing(self):
        self.assertEqual(scope.parse_directory(DOTS+FILE,1),{"plugin.so":12})
    def test_duplicate(self):
        with self.assertRaises(ValueError):
            scope.parse_directory(DOTS+FILE+FILE,2)
    def test_missing_dots(self):
        with self.assertRaises(ValueError):
            scope.parse_directory(FILE,1)
    def test_unsafe_name(self):
        with self.assertRaises(ValueError):
            scope.parse_directory(DOTS+FILE.replace("plugin.so","bad name"),1)
    def test_entry_budget(self):
        with self.assertRaises(ValueError):
            scope.parse_directory(DOTS+FILE,0)


class RealImageScopeTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.parent=Path(tmp.name)
        self.root=self.parent/"root"
        self.root.mkdir()
        for name in scope.FILES:
            path=self.root/name.lstrip("/")
            path.parent.mkdir(parents=True,exist_ok=True)
            path.write_bytes(b"fixture")
        for name in scope.REQUIRED_TREES:
            (self.root/name.lstrip("/")).mkdir(parents=True,exist_ok=True)
        for name in scope.LINKS:
            (self.root/name.lstrip("/")).symlink_to("usr/lib")
        (self.root/"usr/lib/sensor/plugin.so").write_bytes(b"\x7fELFfixture")
        (self.root/"usr/lib/sensor/sub").mkdir()
        (self.root/"usr/lib/sensor/sub/config").write_bytes(b"nested")
        (self.root/"etc/lhd/empty").touch()
        (self.root/"usr/lib/sensor/outside").symlink_to("/etc/passwd")

    def image(self):
        path=self.parent/"image.img"
        with path.open("wb") as f:
            f.truncate(16*1024*1024)
        subprocess.run(["mkfs.ext4","-q","-F","-d",str(self.root),str(path)],
                       check=True,timeout=30)
        return path,hashlib.sha256(path.read_bytes()).hexdigest()

    def test_real_image_parity(self):
        image,sha=self.image()
        result=scope.inspect_image(image,sha)
        directory=inspect(self.root)
        self.assertEqual(result["problems"],directory["problems"])
        self.assertEqual(result["elf_candidates"],directory["elf_candidates"])
        self.assertEqual(result["regular_bytes_hashed"],directory["regular_bytes_hashed"])
        self.assertEqual(set(result["entries"]),set(directory["entries"]))
        for name,entry in directory["entries"].items():
            if "sha256" in entry:
                self.assertEqual(result["entries"][name]["sha256"],entry["sha256"])
        self.assertTrue(result["snapshot_verified"])
        self.assertFalse(result["symlinks_followed"])
        self.assertFalse(result["safe_to_flash"])
        self.assertEqual(hashlib.sha256(image.read_bytes()).hexdigest(),sha)

    def test_config_review_real_image(self):
        for name,raw in (("/etc/nsswitch.conf",b"passwd: files\ngroup: files\nhosts: files dns\n"),
                         ("/etc/hosts",b"192.0.2.1 private-fixture.test\n"),
                         ("/etc/resolv.conf",b"nameserver 192.0.2.2\n"),
                         ("/usr/etc/sensor.xml",b"<sensor/>")):
            (self.root/name.lstrip("/")).write_bytes(raw)
        image,sha=self.image()
        result=scope.inspect_image(image,sha,review_configs=True)
        report=result["extra_config_review"]
        self.assertEqual(report["problems"],[])
        self.assertEqual(report["files"]["/etc/hosts"]["sha256"],
                         result["entries"]["/etc/hosts"]["sha256"])
        self.assertNotIn("private-fixture.test",str(report))
        self.assertNotIn("192.0.2.2",str(report))
        self.assertFalse(report["staging_authorized"])
        self.assertEqual(hashlib.sha256(image.read_bytes()).hexdigest(),sha)

    def test_wrong_digest(self):
        image,_=self.image()
        with self.assertRaises(ValueError):
            scope.inspect_image(image,"0"*64)

    def test_missing_file(self):
        (self.root/"etc/hosts").unlink()
        image,sha=self.image()
        self.assertIn("MISSING:/etc/hosts",scope.inspect_image(image,sha)["problems"])

    def test_hardlink_and_special(self):
        os.link(self.root/"etc/passwd",self.root/"usr/lib/sensor/hard")
        os.mkfifo(self.root/"usr/lib/sensor/fifo")
        image,sha=self.image()
        report=scope.inspect_image(image,sha)
        self.assertIn("HARDLINK_REVIEW:/usr/lib/sensor/hard",report["problems"])
        self.assertIn("SPECIAL_OBJECT_REVIEW:/usr/lib/sensor/fifo",report["problems"])
        self.assertNotIn("sha256",report["entries"]["/usr/lib/sensor/hard"])

    def test_byte_budget(self):
        image,sha=self.image()
        with patch.object(scope,"MAX_TOTAL",3):
            with self.assertRaises(ValueError):
                scope.inspect_image(image,sha)


if __name__=="__main__":
    unittest.main()
