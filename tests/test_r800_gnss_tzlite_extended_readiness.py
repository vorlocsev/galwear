"""Extended readiness is separate from baseline and cannot authorize runtime."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"build"))
import r800_gnss_readiness as r


class ExtendedReadinessTests(unittest.TestCase):
    def setUp(self):
        self.args=(Path("candidate"),Path("image"),"a"*64,"b"*64,"c"*64)
        self.gates=[r.outcome("tizen_image_closure","STATIC_PASS")]
        self.detail={"schema":"r800-tzlite-extended-verify-v1",
                     "status":"EXTENDED_STATIC_IMAGE_MATCH_ONLY",
                     "image_sha256":"a"*64,"review_manifest_sha256":"b"*64,
                     "stage_manifest_sha256":"c"*64,"snapshot_verified":True,
                     "donor_authenticity_verified":False,"ownership_verified":False,
                     "xattrs_verified":False,"runtime_verified":False,"safe_to_flash":False,
                     "file_count":28,"alias_count":3,"extra_plugin_count":1,
                     "excluded_unreviewed_data_count":1,"review_items":["MISSING:/etc/hosts"],
                     "problems":[]}

    def gate(self,changes=None,code=0):
        p=subprocess.CompletedProcess([],code,json.dumps(dict(self.detail,**(changes or {}))).encode(),b"")
        with patch.object(r.subprocess,"run",return_value=p) as run:
            gate=r.extended_tzlite_gate(*self.args,self.gates)
            for digest in self.args[2:]:
                self.assertIn(digest,run.call_args.args[0])
            return gate

    def test_bound_pass(self):
        self.assertEqual(self.gate()["status"],"STATIC_PASS")

    def test_missing_inputs(self):
        for index in range(5):
            args=list(self.args)
            args[index]=None
            with patch.object(r,"static_gate") as call:
                self.assertEqual(r.extended_tzlite_gate(*args,self.gates)["status"],"NOT_TESTED")
                call.assert_not_called()

    def test_prerequisite(self):
        with patch.object(r,"static_gate") as call:
            self.assertEqual(r.extended_tzlite_gate(*self.args,[])["status"],"BLOCKED")
            call.assert_not_called()

    def test_digest_mismatch(self):
        for key in ("image_sha256","review_manifest_sha256","stage_manifest_sha256"):
            self.assertEqual(self.gate({key:"d"*64})["status"],"REVIEW_REQUIRED")

    def test_false_bindings(self):
        for key in ("runtime_verified","ownership_verified","xattrs_verified","donor_authenticity_verified"):
            self.assertEqual(self.gate({key:True})["status"],"REVIEW_REQUIRED")
        self.assertEqual(self.gate({"safe_to_flash":True})["status"],"ERROR")

    def test_invalid_counts_and_review(self):
        for changes in ({"file_count":4},{"alias_count":True},{"extra_plugin_count":65},
                        {"excluded_unreviewed_data_count":-1},{"review_items":None}):
            self.assertEqual(self.gate(changes)["status"],"REVIEW_REQUIRED")

    def test_recheck(self):
        first=self.gate()
        with patch.object(r,"extended_tzlite_gate",return_value=first):
            self.assertTrue(r.extended_tzlite_recheck(first,*self.args,self.gates)["recheck_passed"])
        altered=dict(first,detail=dict(self.detail,file_count=29))
        with patch.object(r,"extended_tzlite_gate",return_value=altered):
            self.assertEqual(r.extended_tzlite_recheck(first,*self.args,self.gates)["status"],"REVIEW_REQUIRED")

    def test_cli_and_runtime_hold(self):
        with tempfile.TemporaryDirectory() as tmp:
            args=["readiness","--tzlite-extended-root",tmp,
                  "--tzlite-extended-review-sha256","b"*64,"--tzlite-extended-stage-sha256","c"*64,
                  "--tizen-image","image","--tizen-image-sha256","a"*64]
            def fake(name,*a,**kw):
                if name=="tzlite_extended_binding":
                    return r.outcome(name,"STATIC_PASS",detail=self.detail,report_sha256="d"*64)
                return r.outcome(name,"STATIC_PASS" if name=="tizen_image_closure" else "NOT_TESTED")
            with patch.object(sys,"argv",args),patch.object(r,"git_state",return_value=("e"*40,True)), \
                 patch.object(r,"static_gate",side_effect=fake) as call,patch("builtins.print") as output:
                self.assertEqual(r.main(),0)
                report=json.loads(output.call_args.args[0])
            self.assertEqual(sum(c.args[0]=="tzlite_extended_binding" for c in call.call_args_list),2)
            self.assertNotIn("tzlite_extended_binding",report["blockers"])
            self.assertTrue(set(r.RUNTIME).issubset(report["blockers"]))
            self.assertEqual(report["decision"],"HOLD_RUNTIME_UNVERIFIED")
            self.assertFalse(report["safe_to_flash"])


if __name__=="__main__":
    unittest.main()
