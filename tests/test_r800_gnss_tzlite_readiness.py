"""Bind the actual tzlite manifest verifier to readiness without promoting runtime."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"build"))
import r800_gnss_readiness as r
import r800_tzlite_manifest as m


class TzliteReadinessTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root=Path(temp.name)
        (self.root/"file").write_bytes(b"synthetic")
        report={"schema":"r800-tzlite-static-stage-v2",
                "status":"TZLITE_STATIC_CANDIDATE_ONLY",
                "source_and_stage_audited":True,"tree":m.inventory(self.root),
                "full_configuration_copied":False,"plugins_complete":False,
                "ownership_preserved":False,"runtime_verified":False,"safe_to_flash":False}
        path=self.root/m.MANIFEST
        path.write_text(json.dumps(report))
        self.digest=hashlib.sha256(path.read_bytes()).hexdigest()

    def gate(self):
        return r.tzlite_integrity_gate(self.root,self.digest)

    def test_actual_verifier(self):
        gate=self.gate()
        self.assertEqual(gate["status"],"STATIC_PASS",gate)
        self.assertEqual(gate["detail"]["manifest_sha256"],self.digest)
        self.assertTrue(r.tzlite_recheck(gate,self.root,self.digest)["recheck_passed"])

    def test_missing_manifest_detail_fails_closed(self):
        with patch.object(r,"static_gate",return_value=r.outcome(
                "tzlite_manifest_integrity","STATIC_PASS")):
            gate=self.gate()
        self.assertEqual(gate["status"],"REVIEW_REQUIRED")
        self.assertIn("MISSING_MANIFEST_DETAIL",gate["problems"])

    def test_recheck_requires_report_digest(self):
        first=self.gate()
        self.assertEqual(first["status"],"STATIC_PASS")
        for digest in (None,"invalid",True):
            with patch.object(r,"tzlite_integrity_gate",return_value=dict(first,report_sha256=digest)):
                self.assertEqual(r.tzlite_recheck(first,self.root,self.digest)["status"],"REVIEW_REQUIRED")

    def test_missing_digest(self):
        self.assertEqual(r.tzlite_integrity_gate(self.root,None)["status"],"NOT_TESTED")

    def test_wrong_digest(self):
        self.assertEqual(r.tzlite_integrity_gate(self.root,"a"*64)["status"],"REVIEW_REQUIRED")

    def test_mutation_detected_on_recheck(self):
        gate=self.gate()
        self.assertEqual(gate["status"],"STATIC_PASS")
        (self.root/"file").write_bytes(b"changed")
        self.assertEqual(r.tzlite_recheck(gate,self.root,self.digest)["status"],"REVIEW_REQUIRED")

    def test_manifest_not_runtime(self):
        report=r.summarize("a"*40,True,[self.gate()])
        self.assertEqual(report["decision"],"HOLD_RUNTIME_UNVERIFIED")
        self.assertTrue(set(r.RUNTIME).issubset(report["blockers"]))
        self.assertFalse(report["daemon_build_authorized"])
        self.assertFalse(report["safe_to_flash"])

    def test_invalid_bindings(self):
        detail={"schema":"r800-tzlite-manifest-check-v1",
                "status":"STATIC_TREE_INTEGRITY_ONLY","manifest_sha256":self.digest,
                "entries":1,"total_bytes":9,"problems":[],
                "donor_authenticity_verified":False,"runtime_verified":False,"safe_to_flash":False}
        for changes in ({"runtime_verified":True},{"donor_authenticity_verified":True},
                        {"manifest_sha256":"a"*64},{"entries":True},{"total_bytes":-1}):
            result=subprocess.CompletedProcess([],0,json.dumps(dict(detail,**changes)).encode(),b"")
            with patch.object(r.subprocess,"run",return_value=result):
                self.assertEqual(self.gate()["status"],"REVIEW_REQUIRED")

    def test_invalid_cli_inputs(self):
        for args in (["--tzlite-manifest-sha256",self.digest],
                     ["--tzlite-root",str(self.root),"--tzlite-manifest-sha256","bad"]):
            with patch.object(sys,"argv",["readiness",*args]), \
                 patch.object(r,"git_state",return_value=("a"*40,True)), \
                 patch.object(r,"static_gate") as gate, patch("builtins.print") as output:
                self.assertEqual(r.main(),2)
                gate.assert_not_called()
                self.assertEqual(json.loads(output.call_args.args[0])["decision"],"REJECT_EVIDENCE")

    def test_cli_order_and_recheck(self):
        actual=self.gate()
        calls=[]
        def fake(name,*args,**kwargs):
            calls.append(name)
            return actual if name==actual["gate"] else r.outcome(name,"NOT_TESTED")
        with patch.object(sys,"argv",["readiness","--tzlite-root",str(self.root),
                                    "--tzlite-manifest-sha256",self.digest]), \
             patch.object(r,"git_state",return_value=("a"*40,True)), \
             patch.object(r,"static_gate",side_effect=fake), patch("builtins.print") as output:
            self.assertEqual(r.main(),0)
            report=json.loads(output.call_args.args[0])
        name="tzlite_manifest_integrity"
        self.assertEqual(calls.count(name),2)
        self.assertLess(calls.index(name),calls.index("tzlite_known_components"))
        self.assertEqual(calls[-1],name)
        gate=next(g for g in report["gates"] if g["gate"]==name)
        self.assertTrue(gate["recheck_passed"])
        self.assertIn("tzlite_known_components",report["blockers"])
        self.assertFalse(report["safe_to_flash"])


if __name__=="__main__":
    unittest.main()
