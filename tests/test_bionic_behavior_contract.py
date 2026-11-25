"""Synthetic console acceptance tests, not execution of Bionic."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"build"))
import r800_bionic_behavior_contract as a

PROVIDER=a.PROVIDERS[2]
LOG=b"\n".join([a.DOMAIN,*a.markers(PROVIDER),a.FIRST_SET])+b"\n"

class BionicContractTests(unittest.TestCase):
    def test_complete(self):
        result=a.inspect(LOG)
        self.assertTrue(result["bionic_memory_reported"])
        self.assertTrue(result["bionic_pthread_tls_reported"])
        self.assertTrue(result["bionic_libdl_libm_reported"])
        self.assertTrue(result["bionic_missing_symbol_reported"])
        self.assertEqual(result["bionic_libm_provider"],PROVIDER)
        self.assertFalse(result["all_runtime_stubs_excluded"])

    def test_each_missing_or_duplicate(self):
        for marker in a.markers(PROVIDER):
            for replacement in (b"",marker+b"\n"+marker):
                with self.subTest(marker=marker,replacement=replacement):
                    with self.assertRaises(ValueError):
                        a.inspect(LOG.replace(marker,replacement))

    def test_wrong_order(self):
        raw=b"\n".join([a.DOMAIN,a.TLS,a.MEMORY,*a.markers(PROVIDER)[2:],a.FIRST_SET])
        self.assertRaises(ValueError,a.inspect,raw)

    def test_bad_provider(self):
        with self.assertRaises(ValueError):
            a.inspect(LOG.replace(PROVIDER.encode(),b"/host/libm.so"))

    def test_outside_client_window(self):
        raw=b"\n".join([*a.markers(PROVIDER),a.DOMAIN,a.FIRST_SET])
        with self.assertRaisesRegex(ValueError,"outside client"):
            a.inspect(raw)

    def test_old_property_only_log_rejected(self):
        with self.assertRaises(ValueError):
            a.inspect(a.DOMAIN+b"\n"+a.FIRST_SET)

    def test_provider_binding(self):
        evidence=a.inspect(LOG)
        plan={"executables":{"/system/bin/galwear_property_client":{"edges":[
              {"needed":"libm.so","resolved":PROVIDER}]}}}
        a.verify_provider(evidence,plan)
        plan["executables"]["/system/bin/galwear_property_client"]["edges"][0]["resolved"]=a.PROVIDERS[0]
        with self.assertRaisesRegex(ValueError,"differs"):
            a.verify_provider(evidence,plan)

    def test_missing_provider_edge(self):
        plan={"executables":{"/system/bin/galwear_property_client":{"edges":[]}}}
        with self.assertRaises(ValueError):
            a.verify_provider(a.inspect(LOG),plan)

if __name__=="__main__":
    unittest.main()
