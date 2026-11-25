"""Synthetic Tizen dependency fixtures; no guest executable is run."""
from pathlib import Path
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/"build"))
from r800_tizen_dependencies import audit, resolve_guest, interpreter
from test_android_linker_audit import fixture, version_fixture

class TizenDependencyTests(unittest.TestCase):
    def setUp(self):
        t=tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        self.root=Path(t.name)
        (self.root/"usr/bin").mkdir(parents=True)
        (self.root/"usr/lib").mkdir()
        (self.root/"lib").symlink_to("/usr/lib")
        self.target="/usr/bin/lhd"

    def put(self,name,data):
        p=self.root/name.lstrip("/")
        p.parent.mkdir(parents=True,exist_ok=True)
        p.write_bytes(data)
        return p

    def test_closure(self):
        self.put(self.target,fixture("arm",needed=["libx.so"]))
        self.put("/usr/lib/libx.so",fixture("arm"))
        r=audit(self.root,[self.target])
        self.assertEqual(r["status"],"TIZEN_STATIC_CLOSURE_ONLY")
        self.assertEqual(len(r["files"]),2)
        self.assertFalse(r["safe_to_flash"])

    def test_required_version_present(self):
        self.put(self.target,version_fixture("arm",need="VER_1"))
        self.put("/usr/lib/libx.so",version_fixture("arm",define="VER_1"))
        r=audit(self.root,[self.target])
        self.assertEqual(r["status"],"TIZEN_STATIC_CLOSURE_ONLY")
        self.assertEqual(r["version_records_checked"],1)

    def test_required_version_absent(self):
        self.put(self.target,version_fixture("arm",need="VER_2"))
        self.put("/usr/lib/libx.so",version_fixture("arm",define="VER_1"))
        r=audit(self.root,[self.target])
        self.assertEqual(r["problems"][0]["reason"],"VERSION_NOT_PROVIDED")

    def test_missing_provider(self):
        self.put(self.target,fixture("arm",needed=["libx.so"]))
        r=audit(self.root,[self.target])
        self.assertEqual(r["problems"][0]["reason"],"MISSING")

    def test_ambiguous_provider(self):
        self.put(self.target,fixture("arm",needed=["libx.so"]))
        self.put("/usr/lib/libx.so",fixture("arm"))
        self.put("/usr/lib/sensor/libx.so",fixture("arm"))
        r=audit(self.root,[self.target])
        self.assertEqual(r["problems"][0]["reason"],"AMBIGUOUS")

    def test_guest_absolute_link(self):
        p=self.put("/usr/lib/libx.so",b"synthetic")
        path,guest=resolve_guest(self.root,"/lib/libx.so")
        self.assertEqual(path,p)
        self.assertEqual(guest,"/usr/lib/libx.so")

    def test_escape(self):
        (self.root/"usr/lib/escape").symlink_to("../../../../etc/passwd")
        with self.assertRaisesRegex(ValueError,"escapes root"):
            resolve_guest(self.root,"/usr/lib/escape")

    def test_wrong_abi(self):
        self.put(self.target,fixture("arm64"))
        r=audit(self.root,[self.target])
        self.assertEqual(r["status"],"TIZEN_DEPENDENCY_REVIEW_REQUIRED")

    def test_interpreter(self):
        data=fixture("arm")
        path=b"/lib/ld-linux.so.3\0"
        struct.pack_into("<H",data,44,3)
        struct.pack_into("<8I",data,116,3,160,0,0,len(path),len(path),4,1)
        data[160:160+len(path)]=path
        self.assertEqual(interpreter(data),"/lib/ld-linux.so.3")
        data[160:164]=b"/bad"
        with self.assertRaisesRegex(ValueError,"Unexpected"):
            interpreter(data)

if __name__=="__main__":
    unittest.main()
