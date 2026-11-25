import sys
from pathlib import Path
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"build"))
from r800_gnss_registration import registration_problems,property_problems,SERVICE,FQ,NAME

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
    def test_unresolved_import(self):
        self.i["unresolved_imports"]=["unknown"]
        self.assertTrue(self.issues())

if __name__=="__main__":
    unittest.main()
