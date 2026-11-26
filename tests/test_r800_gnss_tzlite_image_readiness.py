"""Readiness gate for the paired image and manifest digests."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"build"))
import r800_gnss_readiness as r


class ImageBindingReadinessTests(unittest.TestCase):
    def setUp(self):
        self.image_digest="a"*64
        self.manifest_digest="b"*64
        self.prerequisites=[r.outcome(n,"STATIC_PASS") for n in
            ("tzlite_manifest_integrity","tzlite_known_components","tizen_image_closure")]
        self.detail={"schema":"r800-tzlite-image-binding-v1",
                     "status":"STATIC_IMAGE_COMPONENT_MATCH_ONLY",
                     "image_sha256":self.image_digest,"manifest_sha256":self.manifest_digest,
                     "snapshot_verified":True,"configuration_count":4,"elf_count":24,
                     "alias_count":2,"problems":[],"donor_authenticity_verified":False,
                     "original_ownership_verified":False,"runtime_verified":False,"safe_to_flash":False}

    def gate(self,changes=None,code=0,prerequisites=None):
        result=subprocess.CompletedProcess([],code,json.dumps(dict(self.detail,**(changes or {}))).encode(),b"")
        with patch.object(r.subprocess,"run",return_value=result) as run:
            gate=r.tzlite_image_gate(Path("candidate"),Path("image"),self.image_digest,
                                    self.manifest_digest,self.prerequisites if prerequisites is None else prerequisites)
            self.assertEqual(run.call_count,1 if gate["status"]!="BLOCKED" else 0)
            if run.called:
                args=run.call_args.args[0]
                self.assertIn(self.image_digest,args)
                self.assertIn(self.manifest_digest,args)
            return gate

    def test_bound_static_pass(self):
        self.assertEqual(self.gate()["status"],"STATIC_PASS")

    def test_missing_inputs(self):
        for args in ((None,"img",self.image_digest,self.manifest_digest),
                     ("root",None,None,self.manifest_digest),
                     ("root","img",self.image_digest,None)):
            with patch.object(r,"static_gate") as call:
                self.assertEqual(r.tzlite_image_gate(*args,self.prerequisites)["status"],"NOT_TESTED")
                call.assert_not_called()

    def test_prerequisite_block(self):
        for gate in self.prerequisites:
            prereqs=[g for g in self.prerequisites if g!=gate]
            result=self.gate(prerequisites=prereqs)
            self.assertEqual(result["status"],"BLOCKED")
            self.assertIn(gate["gate"],result["blocked_by"])

    def test_mismatched_hashes(self):
        for key in ("image_sha256","manifest_sha256"):
            result=self.gate({key:"c"*64})
            self.assertEqual(result["status"],"REVIEW_REQUIRED")
            self.assertIn("EVIDENCE_BINDING_MISMATCH:"+key,result["problems"])

    def test_nonrelease_bindings(self):
        for changes in ({"snapshot_verified":1},{"configuration_count":3},
                        {"runtime_verified":True},{"original_ownership_verified":True},
                        {"donor_authenticity_verified":True}):
            self.assertEqual(self.gate(changes)["status"],"REVIEW_REQUIRED")
        self.assertEqual(self.gate({"safe_to_flash":True})["status"],"ERROR")

    def test_count_validation(self):
        for changes in ({"elf_count":0},{"elf_count":True},{"alias_count":-1},
                        {"alias_count":"2"}):
            self.assertEqual(self.gate(changes)["status"],"REVIEW_REQUIRED")

    def test_failed_process(self):
        self.assertEqual(self.gate(code=2)["status"],"REVIEW_REQUIRED")

    def test_final_integrity_required(self):
        first=self.gate()
        for integrity in (r.outcome("tzlite_manifest_integrity","REVIEW_REQUIRED"),
                          r.outcome("tzlite_manifest_integrity","STATIC_PASS")):
            self.assertEqual(r.tzlite_binding_recheck(first,integrity)["status"],"REVIEW_REQUIRED")
        self.assertEqual(r.tzlite_binding_recheck(first,
                         r.outcome("tzlite_manifest_integrity","STATIC_PASS",recheck_passed=True)),first)

    def test_cli_routes_and_revokes(self):
        with tempfile.TemporaryDirectory() as tmp:
            args=["readiness","--tzlite-root",tmp,"--tzlite-manifest-sha256",self.manifest_digest,
                  "--tizen-image","unused.img","--tizen-image-sha256",self.image_digest]
            for final_ok in (True,False):
                def fake(name,*args,**kwargs):
                    if name=="tzlite_manifest_integrity":
                        return r.outcome(name,"STATIC_PASS",detail={"entries":30,"total_bytes":100},
                                         report_sha256="c"*64)
                    if name=="tzlite_image_binding":
                        self.assertEqual(kwargs["bindings"]["image_sha256"],self.image_digest)
                        self.assertEqual(kwargs["bindings"]["manifest_sha256"],self.manifest_digest)
                        return r.outcome(name,"STATIC_PASS")
                    return r.outcome(name,"STATIC_PASS" if name in
                                     ("tzlite_known_components","tizen_image_closure") else "NOT_TESTED")
                def recheck(first,*args):
                    return dict(first,recheck_passed=True) if final_ok else r.outcome(first["gate"],"REVIEW_REQUIRED")
                with patch.object(sys,"argv",args), \
                     patch.object(r,"git_state",return_value=("d"*40,True)), \
                     patch.object(r,"static_gate",side_effect=fake) as call, \
                     patch.object(r,"tzlite_recheck",side_effect=recheck), \
                     patch("builtins.print") as output:
                    self.assertEqual(r.main(),0 if final_ok else 2)
                    report=json.loads(output.call_args.args[0])
                names=[c.args[0] for c in call.call_args_list]
                self.assertLess(names.index("tizen_image_closure"),names.index("tzlite_image_binding"))
                self.assertEqual("tzlite_image_binding" in report["blockers"],not final_ok)
                self.assertTrue(set(r.RUNTIME).issubset(report["blockers"]))
                self.assertEqual(report["decision"],"HOLD_RUNTIME_UNVERIFIED")
                self.assertFalse(report["safe_to_flash"])


if __name__=="__main__":
    unittest.main()
