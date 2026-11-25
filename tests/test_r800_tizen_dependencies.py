"""Synthetic Tizen dependency fixtures; no guest executable is run."""
from pathlib import Path
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/"build"))
from r800_tizen_dependencies import audit, resolve_guest, interpreter
from r800_stage_tizen import stage
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

    def test_stage_closure_and_alias(self):
        self.put(self.target,fixture("arm",needed=["libx.so"]))
        self.put("/usr/lib/libx-real.so",fixture("arm"))
        (self.root/"usr/lib/libx.so").symlink_to("libx-real.so")
        t=tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        output=Path(t.name)/"staged"
        report=stage(self.root,output,[self.target])
        self.assertEqual(report["status"],"TIZEN_ELF_SUBSET_ONLY")
        self.assertEqual((output/"lib/libx.so").read_bytes(),
                         (output/"usr/lib/libx-real.so").read_bytes())
        self.assertFalse((output/"lib/libx.so").is_symlink())
        self.assertFalse(report["safe_to_flash"])

    def test_stage_missing_dependency(self):
        self.put(self.target,fixture("arm",needed=["libx.so"]))
        t=tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        output=Path(t.name)/"staged"
        with self.assertRaisesRegex(ValueError,"Unresolved"):
            stage(self.root,output,[self.target])
        self.assertFalse(output.exists())

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

    def test_hard_float_rejected(self):
        data=fixture("arm")
        struct.pack_into("<I",data,36,0x05000400)
        self.put(self.target,data)
        self.assertTrue(any("Hard-float" in p["reason"] for p in audit(self.root,[self.target])["problems"]))

    def test_et_exec_provider_rejected_even_if_already_visited(self):
        self.put(self.target,fixture("arm",needed=["libx.so"]))
        data=fixture("arm")
        struct.pack_into("<H",data,16,2)
        self.put("/usr/lib/libx.so",data)
        report=audit(self.root,["/usr/lib/libx.so",self.target])
        self.assertIn("INVALID_DYNAMIC_PROVIDER",[p["reason"] for p in report["problems"]])

    def test_soname_mismatch(self):
        self.put(self.target,fixture("arm",needed=["libx.so"]))
        self.put("/usr/lib/libx.so",fixture("arm",sonames=["libother.so"]))
        self.assertIn("SONAME_MISMATCH",[p["reason"] for p in audit(self.root,[self.target])["problems"]])

    def test_unbound_version_need(self):
        data=version_fixture("arm",need="VER_1")
        # Replace DT_NEEDED with an otherwise ignored dynamic tag;
        # keep the version requirement for libx.so intact.
        struct.pack_into("<iI",data,240,21,0)
        self.put(self.target,data)
        self.assertIn("UNBOUND_VERSION_NEED",[p["reason"] for p in audit(self.root,[self.target])["problems"]])

    def test_executable_shared_library_allowed(self):
        self.put(self.target,fixture("arm",needed=["libx.so"]))
        data=fixture("arm",sonames=["libx.so"])
        path=b"/lib/ld-linux.so.3\0"
        struct.pack_into("<H",data,44,3)
        struct.pack_into("<8I",data,116,3,160,0,0,len(path),len(path),4,1)
        data[160:160+len(path)]=path
        self.put("/usr/lib/libx.so",data)
        self.put("/usr/lib/ld-linux.so.3",fixture("arm"))
        self.assertEqual(audit(self.root,[self.target])["problems"],[])

if __name__=="__main__":
    unittest.main()
