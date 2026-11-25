"""Static GPS link contract tests; synthetic metadata only."""
import sys
from pathlib import Path
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"build"))
from r800_gps_link_gate import check_version, import_problems

class GpsLinkGateTests(unittest.TestCase):
    def setUp(self):
        self.imp = {"name":"malloc","type":2,"version":"GLIBC_2.4",
                    "version_library":"libc.so.6","weak":False}
        self.info = {"needed":["libc.so.6"],"version_needs":[
            {"library":"libc.so.6","version":"GLIBC_2.4"}],"symbol_imports":[self.imp]}
        self.providers = {"libc.so.6":{"version_definitions":[{"version":"GLIBC_2.4","base":False}],
                        "symbol_exports":[{"name":"malloc","type":2,"version":"GLIBC_2.4",
                                           "version_hidden":False}]}}

    def test_versions(self):
        for version in ("GLIBC_2.4","GLIBC_2.24","GLIBC_2.24.0"):
            self.assertTrue(check_version(version))
        for version in ("GLIBC_2.25","GLIBC_2.24.1","GLIBC_PRIVATE","GLIBC_ABI_DT_RELR","GLIBCXX_3.4"):
            self.assertFalse(check_version(version))

    def test_matching_provider(self):
        self.assertEqual(import_problems(self.info,self.providers),[])

    def test_missing_symbol(self):
        self.providers["libc.so.6"]["symbol_exports"]=[]
        self.assertIn("No supplied direct provider for: malloc",import_problems(self.info,self.providers))

    def test_missing_weak_symbol(self):
        self.imp["weak"]=True
        self.providers["libc.so.6"]["symbol_exports"]=[]
        self.assertEqual(import_problems(self.info,self.providers),[])

    def test_new_version(self):
        self.info["version_needs"][0]["version"]="GLIBC_2.34"
        self.assertTrue(any("Unsupported version" in p for p in import_problems(self.info,self.providers)))

    def test_wrong_needed(self):
        self.info["needed"].append("libandroid.so")
        self.assertIn("Unexpected DT_NEEDED: libandroid.so",import_problems(self.info,self.providers))

    def test_tls_mismatch(self):
        self.imp["type"]=6
        self.assertIn("No supplied direct provider for: malloc",import_problems(self.info,self.providers))

    def test_private_version_internal_only(self):
        self.imp["version"]="GLIBC_PRIVATE"
        self.info["version_needs"][0]["version"]="GLIBC_PRIVATE"
        self.providers["libc.so.6"]["version_definitions"][0]["version"]="GLIBC_PRIVATE"
        self.providers["libc.so.6"]["symbol_exports"][0]["version"]="GLIBC_PRIVATE"
        self.assertTrue(import_problems(self.info,self.providers))
        self.assertEqual(import_problems(self.info,self.providers,internal=True),[])

    def test_missing_transitive_provider(self):
        self.info["needed"].append("ld-linux.so.3")
        self.assertIn("Unexpected DT_NEEDED: ld-linux.so.3",
                      import_problems(self.info,self.providers,internal=True))

    def test_private_version_missing_definition(self):
        self.info["version_needs"][0]["version"]="GLIBC_PRIVATE"
        self.assertTrue(any("Version absent" in p for p in
                            import_problems(self.info,self.providers,internal=True)))

    def test_unversioned_internal_scope(self):
        self.imp["version"]=None
        self.imp["version_library"]=None
        self.info["needed"]=[]
        self.info["version_needs"]=[]
        self.assertEqual(import_problems(self.info,self.providers,internal=True,
                                         scope=["libc.so.6"]),[])

if __name__ == "__main__":
    unittest.main()
