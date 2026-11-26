"""NSS symbol candidates require strong nonhidden functions."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"build"))
from r800_tzlite_nss_review import export_review
from r800_tzlite_config_review import nsswitch


class NssReviewTests(unittest.TestCase):
    def symbol(self,**changes):
        return dict({"name":"_nss_files_getpwnam_r","type":2,"weak":False,"version_hidden":False},**changes)

    def review(self,exports):
        return export_review({"symbol_exports":exports},"files",{"getpwnam_r"})

    def test_valid(self):
        self.assertEqual(self.review([self.symbol()]),[])

    def test_missing(self):
        self.assertTrue(self.review([]))

    def test_weak(self):
        self.assertTrue(self.review([self.symbol(weak=True)]))

    def test_hidden(self):
        self.assertTrue(self.review([self.symbol(version_hidden=True)]))

    def test_nonfunction(self):
        self.assertTrue(self.review([self.symbol(type=1)]))

    def test_duplicate(self):
        self.assertTrue(self.review([self.symbol(),self.symbol()]))

    def test_database_mapping(self):
        detail=nsswitch(b"passwd: files\ngroup: files\nhosts: files dns\nservices: files\n")
        self.assertEqual(detail["basic_database_providers"]["hosts"],["files","dns"])
        self.assertEqual(detail["other_database_count"],1)
        self.assertNotIn("services",detail["basic_database_providers"])


if __name__=="__main__":
    unittest.main()
