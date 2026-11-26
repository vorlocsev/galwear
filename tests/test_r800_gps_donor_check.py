"""Evidence binding tests; synthetic bytes, no donor execution."""
import hashlib
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"build"))
from r800_gps_donor_check import verify_extraction, unique_marker, DONORS


class DonorEvidenceTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.lib=Path(temp.name)
        self.sha="a"*64
        self.report={"status":"EXT4_DONOR_EXTRACTION_ONLY","profile":"gps-glibc",
                     "image_sha256":self.sha,"snapshot_verified":True,
                     "safe_to_flash":False,"missing_or_ambiguous":[],"files":{}}
        for name in DONORS:
            data=name.encode()
            (self.lib/name).write_bytes(data)
            self.report["files"]["tizen/"+name]={"status":"EXTRACTED","bytes":len(data),
                "sha256":hashlib.sha256(data).hexdigest()}

    def verify(self):
        return verify_extraction(self.report,self.lib,self.sha)

    def test_complete(self):
        self.assertEqual(set(self.verify()),set(DONORS))

    def test_wrong_image(self):
        self.report["image_sha256"]="b"*64
        with self.assertRaises(ValueError): self.verify()

    def test_modified_bytes(self):
        (self.lib/DONORS[0]).write_bytes(b"changed")
        with self.assertRaises(ValueError): self.verify()

    def test_missing_member(self):
        del self.report["files"]["tizen/"+DONORS[0]]
        with self.assertRaises(ValueError): self.verify()

    def test_unexpected_member(self):
        self.report["files"]["extra"]={}
        with self.assertRaises(ValueError): self.verify()

    def test_symlink(self):
        path=self.lib/DONORS[0]
        path.unlink()
        path.symlink_to(self.lib/DONORS[1])
        with self.assertRaises(OSError): self.verify()

    def test_incomplete(self):
        self.report["missing_or_ambiguous"]=["tizen/"+DONORS[0]]
        with self.assertRaises(ValueError): self.verify()

    def test_false_safety_marker_required(self):
        self.report["safe_to_flash"]=True
        with self.assertRaises(ValueError): self.verify()

    def test_marker(self):
        self.assertTrue(unique_marker("X=PASS\n","X=PASS"))
        self.assertFalse(unique_marker("X=PASS\nX=FAIL\n","X=PASS"))
        self.assertFalse(unique_marker("X=PASS\nX=PASS\n","X=PASS"))
        self.assertFalse(unique_marker("prefix X=PASS\n","X=PASS"))


if __name__=="__main__":
    unittest.main()
