"""Synthetic Tizen dependency fixtures; no guest executable is run."""
from pathlib import Path
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/"build"))
from r800_tizen_dependencies import audit, resolve_guest, interpreter
from r800_stage_tizen import stage
from test_android_linker_audit import fixture, version_fixture, classified_symbol_fixture

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

    def test_symbol_version_match(self):
        self.put(self.target,classified_symbol_fixture("arm",version_kind="need"))
        self.put("/usr/lib/libx.so",classified_symbol_fixture("arm",section=1,version_kind="define"))
        r=audit(self.root,[self.target])
        scope=r["symbol_candidates"]["targets"][self.target]
        self.assertEqual(scope["matched"],1)
        self.assertFalse(scope["missing_strong"])
        self.assertFalse(r["symbol_resolution_verified"])

    def test_unrelated_target_cannot_satisfy_import(self):
        self.put(self.target,classified_symbol_fixture("arm"))
        other="/usr/bin/gpsd"
        self.put(other,classified_symbol_fixture("arm",section=1))
        scope=audit(self.root,[self.target,other])["symbol_candidates"]["targets"][self.target]
        self.assertEqual(scope["matched"],0)
        self.assertEqual(len(scope["missing_strong"]),1)

    def test_weak_import_separate(self):
        self.put(self.target,classified_symbol_fixture("arm",binding=2))
        scope=audit(self.root,[self.target])["symbol_candidates"]["targets"][self.target]
        self.assertEqual(len(scope["missing_weak"]),1)
        self.assertFalse(scope["missing_strong"])

    def test_missing_library_makes_symbol_scope_incomplete(self):
        self.put(self.target,classified_symbol_fixture("arm",version_kind="need"))
        scope=audit(self.root,[self.target])["symbol_candidates"]["targets"][self.target]
        self.assertTrue(scope["inventory_incomplete"])
        self.assertEqual(len(scope["incomplete"]),1)
        self.assertFalse(scope["missing_strong"])

    def test_tls_and_relocation_inventory_present(self):
        self.put(self.target,fixture("arm"))
        item=audit(self.root,[self.target])["files"][self.target]
        self.assertIn("tls_segment",item)
        self.assertIn("tls_symbol_count",item)
        self.assertIn("relocations",item)


    def test_strict_page_policy_for_transitive_provider(self):
        self.put(self.target,fixture("arm",needed=["libx.so"]))
        data=fixture("arm")
        struct.pack_into("<H",data,44,3)
        struct.pack_into("<8I",data,116,1,0x200,0x1200,0,0,4,6,1)
        self.put("/usr/lib/libx.so",data)
        normal=audit(self.root,[self.target])
        self.assertEqual(normal["problems"],[])
        self.assertFalse(normal["strict_4k_page_review"])
        strict=audit(self.root,[self.target],strict_pages=True)
        self.assertTrue(strict["strict_4k_page_review"])
        self.assertEqual(strict["status"],"TIZEN_DEPENDENCY_REVIEW_REQUIRED")
        self.assertTrue(any("shared memory page" in p["reason"] for p in strict["problems"]))
        self.assertNotIn("/usr/lib/libx.so",strict["files"])
        self.assertFalse(strict["safe_to_flash"])

    def test_load_geometry_for_exec_and_dyn(self):
        for etype in (2,3):
            with self.subTest(etype=etype):
                data=fixture("arm")
                struct.pack_into("<H",data,16,etype)
                self.put(self.target,data)
                report=audit(self.root,[self.target],strict_pages=True)
                self.assertEqual(report["problems"],[])
                self.assertEqual(report["files"][self.target]["load_review"],
                                 {"nonempty_load_count":1,"strict_4k_page_review":True})
                struct.pack_into("<I",data,52+28,3)
                self.put(self.target,data)
                self.assertTrue(any("PT_LOAD alignment" in p["reason"]
                                    for p in audit(self.root,[self.target])["problems"]))

    def test_overlapping_bss_rejected_by_default(self):
        data=fixture("arm")
        struct.pack_into("<H",data,44,3)
        struct.pack_into("<8I",data,116,1,0,0x1100,0,0,4,6,1)
        self.put(self.target,data)
        report=audit(self.root,[self.target])
        self.assertTrue(any("Overlapping PT_LOAD" in p["reason"] for p in report["problems"]))
        self.assertNotIn(self.target,report["files"])


    def test_stage_rejects_shared_page_before_output(self):
        self.put(self.target,fixture("arm",needed=["libx.so"]))
        data=fixture("arm")
        struct.pack_into("<H",data,44,3)
        struct.pack_into("<8I",data,116,1,0x200,0x1200,0,0,4,6,1)
        self.put("/usr/lib/libx.so",data)
        with tempfile.TemporaryDirectory() as tmp:
            output=Path(tmp)/"staged"
            self.assertEqual(audit(self.root,[self.target])["problems"],[])
            with self.assertRaisesRegex(ValueError,"shared memory page"):
                stage(self.root,output,[self.target])
            self.assertFalse(output.exists())
            self.assertEqual(list(Path(tmp).iterdir()),[])

    def test_stage_persists_strict_load_evidence(self):
        import hashlib
        import json
        self.put(self.target,fixture("arm",needed=["libx.so"]))
        self.put("/usr/lib/libx.so",fixture("arm"))
        with tempfile.TemporaryDirectory() as tmp:
            output=Path(tmp)/"staged"
            report=stage(self.root,output,[self.target])
            evidence=json.loads((output/"tizen-elf-evidence.json").read_text())
            self.assertEqual(evidence,report)
            self.assertTrue(report["strict_4k_page_review"])
            for guest,item in report["files"].items():
                self.assertTrue(item["load_review"]["strict_4k_page_review"])
                self.assertEqual(item["sha256"],hashlib.sha256(
                    (output/guest.lstrip("/")).read_bytes()).hexdigest())
            self.assertFalse(report["safe_to_flash"])
            self.assertFalse(report["runtime_verified"])

    def test_stage_rejects_missing_strict_evidence(self):
        from unittest.mock import patch
        self.put(self.target,fixture("arm"))
        report=audit(self.root,[self.target],strict_pages=True)
        del report["files"][self.target]["load_review"]
        with tempfile.TemporaryDirectory() as tmp:
            output=Path(tmp)/"staged"
            with patch("r800_stage_tizen.audit",return_value=report):
                with self.assertRaisesRegex(ValueError,"Missing strict PT_LOAD evidence"):
                    stage(self.root,output,[self.target])
            self.assertEqual(list(Path(tmp).iterdir()),[])

if __name__=="__main__":
    unittest.main()
