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

    def test_identical_candidates_not_namespace_proof(self):
        infos={"root":elf(None,["a.so"]),"shared":elf("a.so")}
        with patch.object(graph,"inspect",side_effect=lambda raw:infos[raw.decode()]):
            r=graph.walk(lambda p: b"root" if p=="root" else b"shared",
                         lambda name:["art/a","statsd/a"],("root",))
        self.assertEqual(r["edges"][0]["status"],"MULTIPLE_CANDIDATES")
        self.assertTrue(r["edges"][0]["candidate_bytes_identical"])
        self.assertTrue(r["ambiguous_names"]["a.so"]["candidate_bytes_identical"])
        self.assertFalse(r["namespace_resolution_verified"])

    def test_different_candidates_remain_ambiguous(self):
        r=self.run_graph({"root":elf(None,["a.so"]),"a":elf("a.so"),"b":elf("a.so")},
                         {"a.so":["a","b"]})
        self.assertFalse(r["ambiguous_names"]["a.so"]["candidate_bytes_identical"])
        self.assertEqual(len(set(r["ambiguous_names"]["a.so"]["candidate_sha256"].values())),2)

    def test_missing_and_wrong_abi(self):
        r=self.run_graph({"root":elf(None,["a.so","b.so"]),"b":elf("b.so",abi="arm64")},
                         {"b.so":["b"]})
        self.assertEqual(r["counts"],{"NOT_FOUND_IN_SELECTED_DIRS":1,"NO_ELIGIBLE_CANDIDATE":1})
        self.assertIn("b",r["review"])

    def test_wrong_soname(self):
        r=self.run_graph({"root":elf(None,["a.so"]),"b":elf("b.so")},{"a.so":["b"]})
        self.assertEqual(r["edges"][0]["status"],"NO_ELIGIBLE_CANDIDATE")

    def test_observed_dlopen_recurses_without_faking_needed(self):
        infos={"root":elf(None),"palette":elf("libartpalette-system.so",["dep.so"]),
               "dep":elf("dep.so")}
        with patch.object(graph,"inspect",side_effect=lambda raw:infos[raw.decode()]):
            r=graph.walk(lambda p:p.encode(),
                         lambda n:{"libartpalette-system.so":["palette"],"dep.so":["dep"]}[n],
                         ("root",),runtime_loads={"root":("libartpalette-system.so",)})
        self.assertEqual(r["objects"]["root"]["needed"],[])
        self.assertEqual([e["kind"] for e in r["edges"]],["OBSERVED_DLOPEN","DT_NEEDED"])
        self.assertEqual(r["counts"],{"SINGLE_STATIC_CANDIDATE":2})

    def test_missing_observed_dlopen_is_not_success(self):
        with patch.object(graph,"inspect",return_value=elf(None)):
            r=graph.walk(lambda p:b"fixture",lambda n:[],("root",),
                         runtime_loads={"root":("libartpalette-system.so",)})
        self.assertEqual(r["edges"][0]["kind"],"OBSERVED_DLOPEN")
        self.assertEqual(r["edges"][0]["status"],"NOT_FOUND_IN_SELECTED_DIRS")

    def test_vm_requires_original_regular_executable(self):
        sources={"art":("debugfs","image","scratch")}
        with patch.object(graph,"list_directory",return_value={"entries":{"dalvikvm32":{"type":"symlink"}}}), patch.object(graph,"audit") as audit:
            result=graph.audit_vm(sources)
            self.assertEqual(result["status"],"REVIEW_REQUIRED")
            audit.assert_not_called()
        root="art:/bin/dalvikvm32"
        with patch.object(graph,"list_directory",return_value={"entries":{"dalvikvm32":{"type":"regular"}}}), patch.object(graph,"audit",return_value={"objects":{root:{}}, "review":{}, "edges":[]}) as audit:
            result=graph.audit_vm(sources)
            self.assertEqual(result["status"],"DALVIKVM32_STATIC_CANDIDATES_ONLY")
            self.assertFalse(result["java_code_executed"])
            audit.assert_called_once_with(sources,roots=(root,))

    def test_budget(self):
        with patch.object(graph,"MAX_OBJECTS",1):
            with self.assertRaisesRegex(ValueError,"budget"):
                self.run_graph({"root":elf(None,["a.so"]),"a":elf("a.so")},{"a.so":["a"]})

if __name__=="__main__":
    unittest.main()
