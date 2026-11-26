import sys
from pathlib import Path
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"build"))
from r800_gnss_registration import (registration_problems,property_problems,SERVICE,FQ,NAME,
    SEC_SERVICE,SEC_FQ,SEC_NAME,select_service)
from r800_gnss_ipc_layout import identity

class RegistrationTests(unittest.TestCase):
    def setUp(self):
        self.entry={"name":NAME,"format":"hidl","interface":"IGnss","instance":"default",
                    "version":[1,0,0],"transport":"hwbinder"}
        self.v={"files":{"vendor":{"kind":"manifest","type":"device","entries":[self.entry],
                                    "review":[]}},"errors":[]}
        self.s={"name":"vendor.gnss","executable":SERVICE,
                "options":[{"name":"interface","args":[FQ,"default"]}]}
        self.i={"gnss_services":[self.s],"duplicate_services":[],"errors":[],"unresolved_imports":[]}
    def issues(self):
        return registration_problems(self.v,self.i)
    def test_match(self):
        self.assertEqual(self.issues(),[])
    def test_wrong_version(self):
        self.entry["version"]=[2,0,0]
        self.assertTrue(self.issues())
    def test_wrong_transport(self):
        self.entry["transport"]="passthrough"
        self.assertTrue(self.issues())
    def test_wrong_instance(self):
        self.entry["instance"]="other"
        self.assertTrue(self.issues())
    def test_duplicate(self):
        self.v["files"]["vendor"]["entries"].append(dict(self.entry))
        self.assertTrue(self.issues())
    def test_missing_service(self):
        self.i["gnss_services"]=[]
        self.assertTrue(self.issues())
    def test_disabled_without_interface(self):
        self.s["options"]=[{"name":"disabled","args":[]}]
        self.assertTrue(self.issues())
    def test_property_selector(self):
        self.assertEqual(property_problems({"ro.hardware":[{"value":"r800"}]}),[])
        self.assertTrue(property_problems({"ro.hardware":[{"value":"r800"}],
            "ro.hardware.gps":[{"value":"other"}]}))
        self.assertTrue(property_problems({}))
    def samsung(self):
        self.s["executable"]=SEC_SERVICE
        self.s["options"]=[]
        sec=dict(self.entry,name=SEC_NAME,interface="ISecGnss")
        self.v["files"]["vendor"]["entries"].append(sec)
        return sec
    def test_samsung_eager(self):
        self.samsung()
        self.assertEqual(self.issues(),[])
        self.assertEqual(select_service(self.i)["executable"],SEC_SERVICE)
    def test_samsung_missing_manifest(self):
        self.samsung()
        self.v["files"]["vendor"]["entries"].pop()
        self.assertTrue(self.issues())
    def test_samsung_wrong_interface(self):
        self.samsung()["interface"]="IGnss"
        self.assertTrue(self.issues())
    def test_samsung_lazy_both(self):
        self.samsung()
        self.s["options"]=[{"name":"disabled","args":[]},
            {"name":"interface","args":[FQ,"default"]},
            {"name":"interface","args":[SEC_FQ,"default"]}]
        self.assertEqual(self.issues(),[])
        self.s["options"].pop()
        self.assertTrue(self.issues())
    def test_conflicting_services(self):
        self.samsung()
        self.i["gnss_services"].append(dict(self.s,executable=SERVICE,name="aosp"))
        self.assertTrue(self.issues())
    def test_aosp_with_samsung_declaration(self):
        self.samsung()
        self.s["executable"]=SERVICE
        self.assertTrue(self.issues())
    def test_samsung_identity(self):
        self.samsung()
        self.s["source"]="fixture.rc"
        self.s["options"]=[{"name":"user","args":["system"]},
                           {"name":"group","args":["system","gps"]}]
        ids=identity(self.i,{"system":{1000}},{"system":{1000},"gps":{1021}})
        self.assertEqual(ids["uid_candidate"],1000)
        self.assertEqual(ids["supplementary_gid_candidates"],[1021])
    def test_unresolved_import(self):
        self.i["unresolved_imports"]=["unknown"]
        self.assertTrue(self.issues())

if __name__=="__main__":
    unittest.main()
