"""Managed workspace contract tests; no original donor bytes or device I/O."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"build"))
import r800_donor_manager as manager

SOURCE="a"*40
PIN="b"*64


class DonorManagerTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root=Path(tmp.name)
        self.manifest=self.root/"manifest.json"
        self.output=self.root/"output"
        inputs={}
        for name in manager.ROLES:
            path=self.root/name
            if name in ("kernel","components","closure","ndk"):
                path.mkdir()
            else:
                path.write_bytes(name.encode())
            inputs[name]={"path":name}
            if name!="ndk":
                inputs[name]["sha256"]=PIN
        reports={}
        for name in ("system","tizen","j4"):
            path=self.root/(name+".json")
            path.write_text("{}")
            reports[name]={"path":path.name,"sha256":PIN}
            if name!="system":
                reports[name]["archive_sha256"]="c"*64
        self.data={"schema":manager.SCHEMA,"source_sha":SOURCE,"inputs":inputs,
                   "evidence":reports,"xtra_abi":0,"assets":None}

    def load(self,pin=None):
        self.manifest.write_text(json.dumps(self.data))
        with patch.object(manager,"checkout_sha"):
            return manager.load(self.root,self.manifest,pin or manager.sha(self.manifest.read_bytes()),SOURCE)

    def test_exact_input_mapping(self):
        cfg=self.load()
        self.assertEqual(cfg["paths"]["system"],self.root/"system")
        self.assertEqual(cfg["pins"]["system"],PIN)
        self.assertNotIn("ndk",cfg["pins"])
        self.assertEqual(cfg["pixel_evidence"],(self.root/"system.json",PIN))
        self.assertEqual(cfg["stock_evidence"]["j4"],(self.root/"j4.json",PIN,"c"*64))

    def test_wrong_manifest_pin(self):
        with self.assertRaisesRegex(ValueError,"manifest SHA-256 mismatch"):
            self.load("0"*64)

    def test_stale_source(self):
        self.data["source_sha"]="0"*40
        with self.assertRaisesRegex(ValueError,"schema or source SHA"):
            self.load()

    def test_missing_role(self):
        del self.data["inputs"]["base"]
        with self.assertRaisesRegex(ValueError,"Complete manifest input roles"):
            self.load()

    def test_missing_report(self):
        del self.data["evidence"]["j4"]
        with self.assertRaisesRegex(ValueError,"All three donor reports"):
            self.load()

    def test_absolute_path(self):
        self.data["inputs"]["base"]["path"]=str(self.root/"base")
        with self.assertRaisesRegex(ValueError,"workspace-relative"):
            self.load()

    def test_parent_path(self):
        self.data["inputs"]["base"]["path"]="../base"
        with self.assertRaisesRegex(ValueError,"workspace-relative"):
            self.load()

    def test_symlink(self):
        (self.root/"linked").symlink_to(self.root/"base")
        self.data["inputs"]["base"]["path"]="linked"
        with self.assertRaisesRegex(ValueError,"Noncanonical"):
            self.load()

    def test_aliased_input_path(self):
        self.data["inputs"]["base"]["path"]="system"
        with self.assertRaisesRegex(ValueError,"Distinct manifest input paths"):
            self.load()

    def test_invalid_xtra_abi(self):
        self.data["xtra_abi"]=True
        with self.assertRaisesRegex(ValueError,"Invalid XTRA ABI"):
            self.load()

    def test_duplicate_json_keys(self):
        raw=b'{"schema":"one","schema":"two"}'
        self.manifest.write_bytes(raw)
        with patch.object(manager,"checkout_sha"),self.assertRaises(ValueError):
            manager.load(self.root,self.manifest,manager.sha(raw),SOURCE)

    def test_check_does_not_build(self):
        cfg=self.load()
        with patch.object(manager,"preflight") as preflight, \
             patch.object(manager,"verify_pixel",return_value={"fixture":True}) as pixel, \
             patch.object(manager,"stock_bindings",return_value={"fixture":True}) as stock, \
             patch.object(manager,"audit_base",return_value={"identity_blockers":[]}) as base, \
             patch.object(manager,"build") as build:
            report=manager.check(cfg,self.output,SOURCE)
        preflight.assert_called_once()
        pixel.assert_called_once()
        stock.assert_called_once()
        base.assert_called_once_with(self.root/"base",PIN,SOURCE,effects=self.root/"effects",effects_pin=PIN)
        build.assert_not_called()
        self.assertEqual(report["status"],"MANAGED_INPUT_PINS_MATCH_ONLY")
        self.assertFalse(report["safe_to_flash"])
        self.assertFalse(report["ndk_identity_verified"])
        self.assertEqual(report["ndk_selected_tool_status"],"NOT_SUPPLIED")
        self.assertFalse(self.output.exists())


    def test_selected_ndk_pins(self):
        pins={name:PIN for name in manager.NDK_KEYS}
        self.data["inputs"]["ndk"]["tools_sha256"]=pins
        cfg=self.load()
        self.assertEqual(cfg["ndk_pins"],pins)
        with patch.object(manager,"preflight"), \
             patch.object(manager,"verify_pixel",return_value={}), \
             patch.object(manager,"stock_bindings",return_value={}), \
             patch.object(manager,"audit_base",return_value={"identity_blockers":[]}), \
             patch.object(manager,"verify_ndk",return_value={"status":"SELECTED_NDK_TOOL_PINS_MATCH_ONLY"}) as verify:
            result=manager.check(cfg,self.output,SOURCE)
        verify.assert_called_once_with(self.root/"ndk",pins)
        self.assertEqual(result["ndk_selected_tool_status"],"SELECTED_NDK_TOOL_PINS_MATCH_ONLY")

    def test_invalid_selected_ndk_pins(self):
        self.data["inputs"]["ndk"]["tools_sha256"]={"clang":PIN}
        with self.assertRaisesRegex(ValueError,"Invalid NDK selected tool pins"):
            self.load()


    def test_base_identity_review_status(self):
        cfg=self.load()
        with patch.object(manager,"preflight"), \
             patch.object(manager,"verify_pixel",return_value={}), \
             patch.object(manager,"stock_bindings",return_value={}), \
             patch.object(manager,"audit_base",return_value={"identity_blockers":["Missing model"]}):
            report=manager.check(cfg,self.output,SOURCE)
        self.assertEqual(report["status"],"MANAGED_BASE_IDENTITY_REVIEW_REQUIRED")
        self.assertFalse(report["base_vendor_origin_verified"])
        self.assertFalse(report["safe_to_flash"])


    def test_environment_mapping(self):
        for name in ("lock.json","probe.json"):
            (self.root/name).write_text("{}")
        self.data["environment"]={"lock":"lock.json","lock_sha256":PIN,
                                  "probe":"probe.json","probe_sha256":"c"*64}
        cfg=self.load()
        self.assertEqual(cfg["environment"],(self.root/"lock.json",PIN,
                                             self.root/"probe.json","c"*64))
        with patch.object(manager,"preflight"), \
             patch.object(manager,"verify_pixel",return_value={}), \
             patch.object(manager,"stock_bindings",return_value={}), \
             patch.object(manager,"audit_base",return_value={"identity_blockers":[]}), \
             patch.object(manager,"verify_bundle",return_value=(b"lock",b"probe",{"fixture":True})) as verify:
            result=manager.check(cfg,self.output,SOURCE)
        verify.assert_called_once_with(cfg["environment"],SOURCE)
        self.assertEqual(result["host_environment_status"],"SAVED_PROBE_AND_LIVE_SELECTED_TOOLS_ONLY")

    def test_invalid_environment_pins(self):
        self.data["environment"]={"lock":"lock.json","lock_sha256":PIN}
        with self.assertRaisesRegex(ValueError,"Invalid environment lock and probe pins"):
            self.load()


if __name__=="__main__":
    unittest.main()
