"""Synthetic ART candidate graph tests; no proprietary binaries."""
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"build"))
import r800_wear51_art_dependencies as graph

def elf(soname,needed=(),abi="arm"):
    return {"abi":abi,"elf_type":"ET_DYN","has_dynamic":True,
            "custom_search_path":False,"soname":soname,"needed":list(needed)}

class ArtDependenciesTests(unittest.TestCase):
    def run_graph(self,infos,candidates):
        with patch.object(graph,"inspect",side_effect=lambda raw:infos[raw.decode()]):
            return graph.walk(lambda path:path.encode(),lambda name:candidates.get(name,()),("root",))

    def test_transitive_and_cycle(self):
        infos={"root":elf(None,["a.so"]),"a":elf("a.so",["b.so"]),"b":elf("b.so",["a.so"])}
        r=self.run_graph(infos,{"a.so":["a"],"b.so":["b"]})
        self.assertEqual(len(r["objects"]),3)
        self.assertEqual(r["counts"],{"SINGLE_STATIC_CANDIDATE":3})
        self.assertFalse(r["namespace_resolution_verified"])

    def test_ambiguity_preserved(self):
        r=self.run_graph({"root":elf(None,["a.so"]),"a":elf("a.so"),"b":elf("a.so")},
                         {"a.so":["a","b"]})
        self.assertEqual(r["edges"][0]["status"],"MULTIPLE_CANDIDATES")
        self.assertEqual(r["edges"][0]["eligible_candidates"],["a","b"])

    def test_missing_and_wrong_abi(self):
        r=self.run_graph({"root":elf(None,["a.so","b.so"]),"b":elf("b.so",abi="arm64")},
                         {"b.so":["b"]})
        self.assertEqual(r["counts"],{"NOT_FOUND_IN_SELECTED_DIRS":1,"NO_ELIGIBLE_CANDIDATE":1})
        self.assertIn("b",r["review"])

    def test_wrong_soname(self):
        r=self.run_graph({"root":elf(None,["a.so"]),"b":elf("b.so")},{"a.so":["b"]})
        self.assertEqual(r["edges"][0]["status"],"NO_ELIGIBLE_CANDIDATE")

    def test_budget(self):
        with patch.object(graph,"MAX_OBJECTS",1):
            with self.assertRaisesRegex(ValueError,"budget"):
                self.run_graph({"root":elf(None,["a.so"]),"a":elf("a.so")},{"a.so":["a"]})

if __name__=="__main__":
    unittest.main()
