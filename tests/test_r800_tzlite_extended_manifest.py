"""Extended inventory is evidence only; malformed and mismatched paths rejected."""
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"build"))
from r800_tzlite_extended_manifest import build, TARGETS

SHA="a"*64
ELF="/usr/lib/fixture.so"


class ExtendedManifestTests(unittest.TestCase):
    def setUp(self):
        self.inventory={"schema":"r800-tzlite-legacy-image-scope-v1","safe_to_flash":False,
                        "problems":["MISSING:/etc/hosts"],"entries":{
                        "/etc/passwd":{"kind":"regular","bytes":4,"sha256":SHA},
                        "/etc/info.ini":{"kind":"regular","bytes":5,"sha256":SHA},
                        "/etc/localtime":{"kind":"symlink","target":"/outside"},
                        ELF:{"kind":"regular","bytes":6,"sha256":SHA,"elf_candidate":True}}}
        self.plugins={"schema":"r800-tzlite-extra-plugin-audit-v1","safe_to_flash":False,
                      "problems":[],"status":"STATIC_EXTRA_PLUGIN_CLOSURE_ONLY",
                      "dependency_evidence":{"problems":[],"files":{ELF:{"bytes":6,"sha256":SHA}},
                                             "aliases":{p:ELF for p in TARGETS}}}

    def test_categories(self):
        result=build(SHA,self.inventory,self.plugins)
        self.assertEqual(result["category_counts"],{"AUDITED_ELF":1,"KNOWN_CONFIG":1,"UNREVIEWED_DATA":1})
        self.assertEqual(result["total_bytes"],15)
        self.assertNotIn("/etc/localtime",result["files"])
        self.assertIn("MISSING:/etc/hosts",result["review_items"])
        self.assertFalse(result["staging_authorized"])
        self.assertFalse(result["safe_to_flash"])

    def test_deterministic(self):
        self.assertEqual(build(SHA,self.inventory,self.plugins),build(SHA,self.inventory,self.plugins))

    def test_blocked_closure(self):
        self.plugins["problems"]=["bad"]
        result=build(SHA,self.inventory,self.plugins)
        self.assertEqual(result["status"],"BLOCKED_PLUGIN_CLOSURE")
        self.assertEqual(result["files"],{})

    def test_hash_mismatch(self):
        self.inventory["entries"][ELF]["sha256"]="b"*64
        with self.assertRaises(ValueError):
            build(SHA,self.inventory,self.plugins)

    def test_extra_elf_excluded(self):
        path="/etc/lhd/unreviewed.so"
        self.inventory["entries"][path]={"kind":"regular","bytes":4,"sha256":SHA,"elf_candidate":True}
        result=build(SHA,self.inventory,self.plugins)
        self.assertNotIn(path,result["files"])
        self.assertIn("ELF_OUTSIDE_AUDITED_CLOSURE:"+path,result["review_items"])

    def test_path_collision(self):
        self.inventory["entries"][TARGETS[0]]={"kind":"regular","bytes":1,"sha256":SHA}
        with self.assertRaises(ValueError):
            build(SHA,self.inventory,self.plugins)

    def test_unsafe_path(self):
        self.inventory["entries"]["/etc/../escape"]={"kind":"regular","bytes":1,"sha256":SHA}
        with self.assertRaises(ValueError):
            build(SHA,self.inventory,self.plugins)


if __name__=="__main__":
    unittest.main()
