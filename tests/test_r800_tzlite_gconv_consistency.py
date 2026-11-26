"""External gconv edge consistency is not conversion execution."""
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"build"))
from r800_tzlite_gconv_consistency import compare
from r800_tzlite_cache_review import GCONV
from r800_tzlite_metadata_plan import digest

SHA="a"*64
P="/usr/lib/gconv/FIXTURE.so"


class ConsistencyTests(unittest.TestCase):
    def setUp(self):
        self.plugins={"schema":"r800-tzlite-extra-plugin-audit-v1","safe_to_flash":False,"problems":[]}
        self.edge={"from":"UTF-16//","to":"INTERNAL","path":P}
        self.cache={"schema":"r800-tzlite-cache-review-v1","safe_to_flash":False,
                    "plugin_audit_sha256":digest(self.plugins),"files":{GCONV:{
                    "status":"STATIC_TABLE_INVENTORY_ONLY","module_paths":[P],
                    "conversion_references":[dict(self.edge)]}}}
        self.gconv={"schema":"r800-tzlite-gconv-review-v1","safe_to_flash":False,
                    "plugin_audit_sha256":digest(self.plugins),"status":"STATIC_GCONV_CANDIDATES_ONLY",
                    "problems":[],"configuration":{"aliases":{},"module_paths":[P],"conversions":[dict(self.edge)]},
                    "modules":{P:{"status":"STATIC_GCONV_MODULE_CANDIDATE_ONLY","canonical":P,"sha256":SHA,"problems":[]}},
                    "dependency_evidence":{"aliases":{P:P},"files":{P:{"sha256":SHA}}}}
    def run_compare(self):
        return compare(SHA,self.plugins,self.cache,self.gconv)
    def test_match(self):
        result=self.run_compare()
        self.assertEqual(result["status"],"STATIC_EXTERNAL_REFERENCE_MATCH_ONLY")
        self.assertFalse(result["staging_authorized"])
        self.assertFalse(result["runtime_verified"])
    def test_reverse_direction(self):
        self.cache["files"][GCONV]["conversion_references"][0].update(
            {"from":"INTERNAL","to":"UTF-16//"})
        result=self.run_compare()
        self.assertEqual(len(result["text_only"]),1)
        self.assertEqual(len(result["cache_only"]),1)
    def test_alias(self):
        self.gconv["configuration"]["aliases"]={"UTF16//":"UTF-16//"}
        self.cache["files"][GCONV]["conversion_references"][0]["from"]="UTF16//"
        self.assertEqual(self.run_compare()["status"],"STATIC_EXTERNAL_REFERENCE_MATCH_ONLY")
    def test_bad_hash(self):
        self.gconv["modules"][P]["sha256"]="b"*64
        self.assertEqual(self.run_compare()["unverified_modules"],[P])
    def test_prerequisite(self):
        self.gconv["status"]="REVIEW_REQUIRED"
        self.assertEqual(self.run_compare()["problems"],["GCONV_CONSISTENCY_PREREQUISITE_REVIEW"])
    def test_binding(self):
        self.cache["plugin_audit_sha256"]="b"*64
        with self.assertRaises(ValueError):
            self.run_compare()
    def test_path_inventory(self):
        self.cache["files"][GCONV]["module_paths"]=[]
        with self.assertRaises(ValueError):
            self.run_compare()


if __name__=="__main__":
    unittest.main()
