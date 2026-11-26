"""Review plan remains non-executable and bound to exact evidence."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"build"))
from r800_tzlite_metadata_plan import plan, digest


class PlanTests(unittest.TestCase):
    def setUp(self):
        self.src={"entries":{"/usr/bin/lhd":{"kind":"regular","mode":"0o4755",
                    "links":2,"xattr_inventory":{"attributes":{"security.capability":{}}}}}}
        self.comparison={"staged_metadata":{"/usr/bin/lhd":{"kind":"regular","mode":"0o755",
                    "xattr_names":[]}},
                    "metadata_differences":{"/usr/bin/lhd":{"status":"METADATA_DIFFERS",
                        "fields":{"uid":{"original":100,"staged":1000},
                                  "mode":{"original":"0o4755","staged":"0o755"}},
                        "reported_original_xattrs_not_staged":["security.capability"]}},
                    "access_comparison":{"files":{"/usr/bin/lhd":{"read":{
                        "status":"DIFFERENT_CANDIDATE","original":"CONDITIONAL_MODE_CANDIDATE",
                        "staged":"DENIED_CANDIDATE"}}},"aliases":{}}}

    def run_plan(self,problems=()):
        return plan("a"*64,"b"*64,problems,self.src,self.comparison)

    def test_binding(self):
        result=self.run_plan()
        self.assertEqual(result["image_sha256"],"a"*64)
        self.assertEqual(result["manifest_sha256"],"b"*64)
        self.assertEqual(result["comparison_sha256"],digest(self.comparison))
        self.assertEqual(result["original_metadata_sha256"],digest(self.src))
        self.assertEqual(result,self.run_plan())

    def test_content_mismatch_blocks(self):
        result=self.run_plan(["IMAGE_CONFIGURATION_HASH_MISMATCH"])
        self.assertEqual(result["status"],"BLOCKED_CONTENT_MISMATCH")
        self.assertEqual(result["items"],[])

    def test_invalid_digest(self):
        with self.assertRaises(ValueError):
            plan("bad","b"*64,[],self.src,self.comparison)

    def test_categories(self):
        cats={i["category"] for i in self.run_plan()["items"] if i["path"]=="/usr/bin/lhd"}
        self.assertEqual(cats,{"OWNERSHIP_REVIEW","MODE_REVIEW","XATTR_REVIEW",
                               "PRIVILEGE_REVIEW","ACCESS_REVIEW","PATH_LAYOUT_REVIEW"})

    def test_identical_privileges_still_review(self):
        self.comparison["metadata_differences"]={}
        self.comparison["staged_metadata"]["/usr/bin/lhd"]["mode"]="0o4755"
        self.comparison["staged_metadata"]["/usr/bin/lhd"]["xattr_names"]=["security.capability"]
        self.assertTrue(any(i["category"]=="PRIVILEGE_REVIEW" and i["path"]=="/usr/bin/lhd"
                            for i in self.run_plan()["items"]))

    def test_equal_denied_still_review(self):
        rec=self.comparison["access_comparison"]["files"]["/usr/bin/lhd"]["read"]
        rec.update(status="SAME_CANDIDATE_CLASS",original="DENIED_CANDIDATE")
        self.assertTrue(any(i["category"]=="ACCESS_REVIEW" for i in self.run_plan()["items"]))

    def test_scope_and_mounts(self):
        result=self.run_plan()
        self.assertTrue(any(i["category"]=="RUNTIME_MOUNT_REVIEW" and i["path"]=="/opt"
                            for i in result["items"]))
        self.assertTrue(any(i["category"]=="EXTERNAL_PAYLOAD_REVIEW" for i in result["items"]))
        self.assertEqual(sum(result["category_counts"].values()),len(result["items"]))

    def test_never_authorizes(self):
        for result in (self.run_plan(),self.run_plan(["mismatch"])):
            for k in ("execution_authorized","ownership_restoration_authorized",
                      "privilege_restoration_authorized","runtime_verified","safe_to_flash"):
                self.assertIs(result[k],False)
            self.assertTrue(all(i["disposition"]=="REVIEW_ONLY" for i in result["items"]))


if __name__=="__main__":
    unittest.main()
