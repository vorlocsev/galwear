import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"build"))
import r800_gnss_readiness as r

class ReadinessTests(unittest.TestCase):
    def static(self,code,data):
        result=subprocess.CompletedProcess([],code,json.dumps(data).encode(),b"")
        with patch.object(r.subprocess,"run",return_value=result):
            return r.static_gate("link","unused.py",["x"],"STATIC_ONLY")
    def test_missing_inputs(self):
        self.assertEqual(r.static_gate("link","unused",None,"STATIC_ONLY")["status"],"NOT_TESTED")
    def test_static_only(self):
        self.assertEqual(self.static(0,{"status":"STATIC_ONLY","problems":[],"safe_to_flash":False})["status"],"STATIC_PASS")
    def test_failure(self):
        self.assertEqual(self.static(2,{"status":"STATIC_ONLY","problems":[],"safe_to_flash":False})["status"],"REVIEW_REQUIRED")
    def test_missing_problems(self):
        self.assertEqual(self.static(0,{"status":"STATIC_ONLY","safe_to_flash":False})["status"],"ERROR")
    def test_false_flash_marker(self):
        self.assertEqual(self.static(0,{"status":"STATIC_ONLY","problems":[],"safe_to_flash":True})["status"],"ERROR")
    def test_dirty(self):
        self.assertEqual(r.offline_gate(True,"a"*40,False)["status"],"BLOCKED")
    def test_markers(self):
        sha="a"*40
        lines=["SOURCE_SHA="+sha,"GPS_OFFLINE_COMPILE_GATE=PASS","DONOR_LINK_VERIFIED=false",
               "QEMU_RUNTIME_VERIFIED=false","GNSS_RUNTIME_VERIFIED=false","safe_to_flash=false"]
        with patch.object(r,"git_state",return_value=(sha,True)):
            for extra,expected in (([],"PASS"),(["GPS_OFFLINE_COMPILE_GATE=PASS"],"FAILED"),
                                   (["safe_to_flash=true"],"FAILED"),
                                   (["DONOR_LINK_VERIFIED=true"],"FAILED"),
                                   (["SOURCE_SHA="+"b"*40],"FAILED")):
                result=subprocess.CompletedProcess([],0,"\n".join(lines+extra).encode(),b"")
                with patch.object(r.subprocess,"run",return_value=result):
                    self.assertEqual(r.offline_gate(True,sha,True)["status"],expected)
    def test_partial_link_inputs_rejected(self):
        for flag in ("--binary", "--libdir"):
            with patch.object(sys,"argv",["readiness",flag,"unused"]), \
                 patch.object(r,"git_state",return_value=("a"*40,True)), \
                 patch.object(r,"static_gate") as gate, \
                 patch("builtins.print") as output:
                self.assertEqual(r.main(),2)
                gate.assert_not_called()
                report=json.loads(output.call_args.args[0])
                self.assertEqual(report["decision"],"REJECT_EVIDENCE")
                self.assertFalse(report["safe_to_flash"])
    def image_gate(self, changes=None, code=0):
        expected={"schema":"r800-gnss-image-audit-v1","image_sha256":"c"*64,
                  "snapshot_verified":True,"runtime_paths_verified":False,
                  "donor_authenticity_verified":False,"hardware_interface_abi_verified":False,
                  "gnss_runtime_verified":False}
        data=dict(expected,status="STATIC_IMAGE_GNSS_CLOSURE_ONLY",problems=[],safe_to_flash=False)
        data.update(changes or {})
        result=subprocess.CompletedProcess([],code,json.dumps(data).encode(),b"")
        with patch.object(r.subprocess,"run",return_value=result):
            return r.static_gate("tizen_image_closure","unused.py",["x"],
                "STATIC_IMAGE_GNSS_CLOSURE_ONLY",bindings=expected,timeout=600)

    def test_image_evidence_bound(self):
        self.assertEqual(self.image_gate()["status"],"STATIC_PASS")

    def test_image_wrong_hash(self):
        gate=self.image_gate({"image_sha256":"d"*64})
        self.assertEqual(gate["status"],"REVIEW_REQUIRED")
        self.assertIn("EVIDENCE_BINDING_MISMATCH:image_sha256",gate["problems"])

    def test_image_snapshot_boolean(self):
        for value in (False,1,None):
            self.assertEqual(self.image_gate({"snapshot_verified":value})["status"],"REVIEW_REQUIRED")

    def test_image_no_runtime_claim(self):
        for key in ("runtime_paths_verified","donor_authenticity_verified",
                    "hardware_interface_abi_verified","gnss_runtime_verified"):
            self.assertEqual(self.image_gate({key:True})["status"],"REVIEW_REQUIRED")

    def test_image_failure(self):
        self.assertEqual(self.image_gate(code=2)["status"],"REVIEW_REQUIRED")

    def test_image_inputs_pair_required(self):
        for args in (["--tizen-image","unused"],["--tizen-image-sha256","c"*64],
                     ["--tizen-image","unused","--tizen-image-sha256","bad"]):
            with patch.object(sys,"argv",["readiness"]+args), \
                 patch.object(r,"git_state",return_value=("a"*40,True)), \
                 patch.object(r,"static_gate") as gate, patch("builtins.print") as output:
                self.assertEqual(r.main(),2)
                gate.assert_not_called()
                self.assertEqual(json.loads(output.call_args.args[0])["decision"],"REJECT_EVIDENCE")

    def test_image_main_routes_gate_without_claiming_runtime(self):
        sha="a"*40
        digest="c"*64
        with patch.object(sys,"argv",["readiness","--tizen-image","unused",
                                     "--tizen-image-sha256",digest]), \
             patch.object(r,"git_state",return_value=(sha,True)), \
             patch.object(r,"static_gate",side_effect=lambda name,*a,**kw:
                 r.outcome(name,"STATIC_PASS" if name=="tizen_image_closure" else "NOT_TESTED")) as gate, \
             patch("builtins.print") as output:
            self.assertEqual(r.main(),0)
            report=json.loads(output.call_args.args[0])
            image_call=next(c for c in gate.call_args_list if c.args[0]=="tizen_image_closure")
            self.assertEqual(image_call.kwargs["bindings"]["image_sha256"],digest)
            self.assertEqual(image_call.kwargs["timeout"],600)
            self.assertNotIn("tizen_image_closure",report["blockers"])
            self.assertTrue(set(r.RUNTIME).issubset(report["blockers"]))
            self.assertIn("tizen_preflight",report["blockers"])
            self.assertFalse(report["safe_to_flash"])

    def test_qemu_requires_explicit_complete_inputs(self):
        with patch.object(sys,"argv",["readiness","--donor-qemu"]), \
             patch.object(r,"git_state",return_value=("a"*40,True)), \
             patch.object(r,"run_donor") as launch, patch("builtins.print") as output:
            self.assertEqual(r.main(),2)
            launch.assert_not_called()
            self.assertEqual(json.loads(output.call_args.args[0])["decision"],"REJECT_EVIDENCE")

    def test_hold_even_when_static_passes(self):
        report=r.summarize("a"*40,True,[r.outcome("link","STATIC_PASS")])
        self.assertFalse(report["safe_to_flash"])
        self.assertFalse(report["daemon_build_authorized"])
        self.assertFalse(report["ci_verified"])
        self.assertEqual(report["decision"],"HOLD_RUNTIME_UNVERIFIED")
        self.assertEqual(set(report["blockers"]),set(r.RUNTIME))

if __name__=="__main__":
    unittest.main()
