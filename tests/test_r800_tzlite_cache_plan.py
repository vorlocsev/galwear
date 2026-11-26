"""Cache planning must not turn source cache records into deployment instructions."""
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"build"))
from r800_tzlite_cache_plan import plan, LD, GCONV
from r800_tzlite_metadata_plan import digest

SHA="a"*64
LIB="/usr/lib/libfixture.so"
ALIAS="/lib/libfixture.so"


class CachePlanTests(unittest.TestCase):
    def setUp(self):
        self.plugins={"schema":"r800-tzlite-extra-plugin-audit-v1","safe_to_flash":False,
                      "problems":[],"dependency_evidence":{"files":{LIB:{"bytes":10,"sha256":SHA,
                      "soname":"libfixture.so"}},"aliases":{ALIAS:LIB}}}
        self.manifest={"schema":"r800-tzlite-extended-manifest-v1","image_sha256":SHA,
                       "safe_to_flash":False,"status":"REVIEW_REQUIRED","plugin_audit_sha256":digest(self.plugins),
                       "files":{LIB:{"bytes":10,"sha256":SHA,"category":"AUDITED_ELF"}},
                       "aliases":{ALIAS:{"canonical":LIB,"disposition":"REVIEW_ONLY"}}}
        self.record={"name":"libfixture.so","path":ALIAS,"canonical":LIB,"sha256":SHA,
                     "status":"AUDITED_PATH_CANDIDATE","flags":3,"hwcap":0,"osversion":0}
        self.cache={"schema":"r800-tzlite-cache-review-v1","safe_to_flash":False,
                    "plugin_audit_sha256":digest(self.plugins),"files":{
                    LD:{"status":"STATIC_TABLE_INVENTORY_ONLY","records":[self.record]},
                    GCONV:{"status":"STATIC_TABLE_INVENTORY_ONLY","records":[]}}}
    def run_plan(self):
        return plan(SHA,self.manifest,self.cache,self.plugins)
    def test_candidate(self):
        r=self.run_plan()
        self.assertEqual(r["loader_candidates"][0]["path"],ALIAS)
        self.assertFalse(r["cache_generation_authorized"])
        self.assertFalse(r["original_cache_reuse_authorized"])
    def test_missing(self):
        self.cache["files"][LD]["records"]=[dict(self.record,path="/opt/lib.so",canonical=None,
                                          sha256=None,status="NOT_IN_AUDITED_SUBSET")]
        r=self.run_plan()
        self.assertEqual(r["excluded_loader_records"][0]["reason"],"PATH_ABSENT")
    def test_duplicate(self):
        self.cache["files"][LD]["records"].append(dict(self.record,path=LIB))
        self.assertEqual(self.run_plan()["loader_candidates"],[])
    def test_hwcap(self):
        self.record["hwcap"]=1
        self.assertEqual(self.run_plan()["excluded_loader_records"][0]["reason"],"LOADER_SELECTION_REVIEW")
    def test_hash_mismatch(self):
        self.record["sha256"]="b"*64
        with self.assertRaises(ValueError):
            self.run_plan()
    def test_digest_mismatch(self):
        self.manifest["plugin_audit_sha256"]="b"*64
        with self.assertRaises(ValueError):
            self.run_plan()
    def test_gconv_missing(self):
        self.cache["files"][GCONV]["records"]=[{"path":"/usr/lib/gconv/X.so","canonical":None,
                  "sha256":None,"status":"NOT_IN_AUDITED_SUBSET"}]
        self.assertEqual(self.run_plan()["gconv_missing_paths"],["/usr/lib/gconv/X.so"])
    def test_blocked(self):
        self.manifest["status"]="BLOCKED_PLUGIN_CLOSURE"
        self.assertEqual(self.run_plan()["status"],"BLOCKED_PLUGIN_CLOSURE")


if __name__=="__main__":
    unittest.main()
