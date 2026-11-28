"""Synthetic loader listing fixtures. No actual loader or guest execution."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"build"))
import r800_linux_loader_observation as obs

ROOT="/usr/bin/fixture"
LIB="/usr/lib/x86_64-linux-gnu/libfixture.so"
LOADER="/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"
LISTING="""linux-vdso.so.1 (0x1234)
libfixture.so => /lib/x86_64-linux-gnu/libfixture.so (0xabcd)
/lib64/ld-linux-x86-64.so.2 (0x5678)
"""


class LoaderObservationTests(unittest.TestCase):
    def setUp(self):
        self.report={"objects":{
            ROOT:{"needed":["libfixture.so"],"interpreter":obs.LOADER},
            LIB:{"needed":["ld-linux-x86-64.so.2"],"interpreter":None},
            LOADER:{"needed":[],"interpreter":None}},
            "bindings":{"fixture":ROOT,"libfixture.so":LIB,
                        obs.LOADER:LOADER,"ld-linux-x86-64.so.2":LOADER}}

    def resolve(self,path):
        return {"/lib/x86_64-linux-gnu/libfixture.so":LIB,obs.LOADER:LOADER}.get(path,path)

    def compare(self,listing=LISTING):
        return obs.compare_listing(self.report,"fixture",listing,self.resolve)

    def test_exact_transitive_listing(self):
        result=self.compare()
        self.assertEqual(result["providers"],{"libfixture.so":LIB,obs.LOADER:LOADER})
        self.assertTrue(result["vdso_observed"])

    def test_aslr_addresses_are_not_identity(self):
        self.assertEqual(self.compare(),self.compare(LISTING.replace("0x1234","0x99")))

    def test_missing_dependency(self):
        with self.assertRaisesRegex(ValueError,"Expected dependency not observed"):
            self.compare(LISTING.replace("libfixture.so => /lib/x86_64-linux-gnu/libfixture.so (0xabcd)\n",""))

    def test_missing_loader(self):
        with self.assertRaisesRegex(ValueError,"Expected loader not observed"):
            self.compare(LISTING.replace("/lib64/ld-linux-x86-64.so.2 (0x5678)\n",""))

    def test_unpinned_provider(self):
        with self.assertRaisesRegex(ValueError,"unpinned object"):
            self.compare(LISTING.replace("/lib/x86_64-linux-gnu/libfixture.so","/tmp/libfixture.so"))

    def test_not_found(self):
        with self.assertRaisesRegex(ValueError,"unresolved loader listing"):
            self.compare("libfixture.so => not found\n")

    def test_duplicate_provider(self):
        with self.assertRaisesRegex(ValueError,"Duplicate loader dependency"):
            self.compare(LISTING+LISTING.splitlines()[1]+"\n")

    def test_unexpected_named_provider(self):
        with self.assertRaisesRegex(ValueError,"differs from static candidate"):
            self.compare(LISTING+"libextra.so => "+LIB+" (0x777)\n")


if __name__=="__main__":
    unittest.main()
