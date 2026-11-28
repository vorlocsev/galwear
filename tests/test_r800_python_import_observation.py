"""Synthetic import observation review; no project or guest program execution."""
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"build"))
import r800_python_import_observation as obs

PIN="a"*64


class ImportObservationTests(unittest.TestCase):
    def setUp(self):
        self.sources={n:{"path":"/fixture/build/"+n+".py","sha256":PIN,"bytes":1}
                      for n in obs.TARGETS}
        self.runtime={"stdlib":{"files":{
            "json/__init__.py":{"kind":"regular","sha256":PIN,"bytes":1},
            "json/__pycache__/__init__.cpython-312.pyc":{"kind":"regular","sha256":"b"*64,"bytes":2}}}}
        self.observed={"flags":{"isolated":1,"no_site":1,"ignore_environment":1,
                                 "dont_write_bytecode":True},
                       "initial_path":list(obs.PATHS),"final_path":list(obs.PATHS),
                       "modules":{n:{"origin":r["path"],"cached":None} for n,r in self.sources.items()}}
        self.observed["modules"].update({
            "sys":{"origin":"built-in","cached":None},
            "json":{"origin":str(obs.ROOT/"json/__init__.py"),
                    "cached":str(obs.ROOT/"json/__pycache__/__init__.cpython-312.pyc")}})

    def review(self):
        return obs.review(self.observed,self.sources,self.runtime)

    def test_exact_origins(self):
        rows=self.review()
        self.assertEqual(rows["json"]["cached_candidate_sha256"],"b"*64)
        self.assertEqual(rows["sys"],{"kind":"built-in"})
        self.assertTrue(all(rows[n]["kind"]=="tracked_source" for n in obs.TARGETS))

    def test_path_mutation(self):
        self.observed["final_path"].append("/tmp")
        with self.assertRaisesRegex(ValueError,"path or flags"):
            self.review()

    def test_sitecustomize(self):
        self.observed["modules"]["sitecustomize"]={"origin":"frozen","cached":None}
        with self.assertRaisesRegex(ValueError,"site initialization"):
            self.review()

    def test_untracked_module(self):
        self.observed["modules"]["external"]={"origin":"/fixture/build/external.py","cached":None}
        with self.assertRaisesRegex(ValueError,"external module origin"):
            self.review()

    def test_unpinned_stdlib(self):
        self.observed["modules"]["json"]["origin"]=str(obs.ROOT/"unknown.py")
        with self.assertRaisesRegex(ValueError,"origin not pinned"):
            self.review()

    def test_unpinned_cache(self):
        self.observed["modules"]["json"]["cached"]=str(obs.ROOT/"unknown.pyc")
        with patch.object(obs.Path,"exists",return_value=True):
            with self.assertRaisesRegex(ValueError,"Unpinned bytecode"):
                self.review()

    def test_missing_target(self):
        del self.observed["modules"][obs.TARGETS[0]]
        with self.assertRaisesRegex(ValueError,"Incomplete import"):
            self.review()

    def test_wrong_target_origin(self):
        self.observed["modules"][obs.TARGETS[0]]={"origin":"built-in","cached":None}
        with self.assertRaisesRegex(ValueError,"target origin"):
            self.review()


if __name__=="__main__":
    unittest.main()
