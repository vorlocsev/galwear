"""Offline capacity estimates only; no physical storage access."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"build"))
import r800_storage_estimate as storage


class StorageEstimateTests(unittest.TestCase):
    def setUp(self):
        self.files={storage.VENDOR:{"bytes":8193},
                    "r800dev/android/system.img":{"bytes":4097},
                    "r800dev/bin/busybox":{"bytes":1},
                    "vendor/lib/hw/gps.r800.so":{"bytes":9999}}
        self.dirs={"r800dev/tzlite/dev":"0o755"}
        self.kernel={"development-boot/Image":{"bytes":1024},
                     "development-boot/r800.dtb":{"bytes":storage.DT_SIZE},
                     "development-boot/init":{"bytes":64}}
        self.observed={"schema":storage.SCHEMA,"model":"SM-R800",
                       "scope":"OPERATOR_REPORTED_READ_ONLY",
                       "partitions":{n:{"block_size":4096,"available_blocks":100,
                           "available_inodes":100,"reserve_bytes":4096,"reserve_inodes":1}
                           for n in ("p15","p17")}}

    def estimate(self,observed=None):
        return storage.estimate(self.files,self.dirs,self.kernel,observed)

    def test_unmeasured_never_assumes_capacity(self):
        r=self.estimate()
        self.assertEqual(r["partitions"]["p17"]["status"],"CAPACITY_NOT_MEASURED")
        self.assertEqual(r["preserved_partitions"],["p16","p18"])
        self.assertEqual(r["excluded_provenance_bytes"],9999)
        self.assertEqual(r["excluded_kernel_evidence_bytes"],64)
        self.assertFalse(r["safe_to_flash"])

    def test_allocation_and_reserve(self):
        r=self.estimate(self.observed)
        p15=r["partitions"]["p15"]
        self.assertEqual(p15["allocation_lower_bound_bytes"],4*4096)
        self.assertEqual(p15["estimated_required_bytes"],5*4096)
        self.assertEqual(p15["estimated_required_inodes"],3)
        p17=r["partitions"]["p17"]
        self.assertEqual(p17["directories"],5)
        self.assertEqual(p17["allocation_lower_bound_bytes"],8*4096)
        self.assertEqual(p17["status"],"ESTIMATE_FITS_REPORTED_CAPACITY")
        self.assertFalse(r["partition_size_verified"])

    def test_insufficient_blocks(self):
        self.observed["partitions"]["p15"]["available_blocks"]=4
        self.assertEqual(self.estimate(self.observed)["partitions"]["p15"]["status"],
                         "ESTIMATE_EXCEEDS_REPORTED_CAPACITY")

    def test_insufficient_inodes(self):
        self.observed["partitions"]["p17"]["available_inodes"]=1
        self.assertEqual(self.estimate(self.observed)["partitions"]["p17"]["status"],
                         "ESTIMATE_EXCEEDS_REPORTED_CAPACITY")

    def test_never_budget_p18(self):
        self.observed["partitions"]["p18"]=self.observed["partitions"]["p17"]
        with self.assertRaisesRegex(ValueError,"Only p15 and p17"):
            self.estimate(self.observed)

    def test_invalid_reserve(self):
        self.observed["partitions"]["p15"]["reserve_bytes"]=0
        with self.assertRaisesRegex(ValueError,"Invalid capacity or reserve"):
            self.estimate(self.observed)

    def test_boot_minimum_exceeds(self):
        self.kernel["development-boot/Image"]["bytes"]=storage.PARTITION
        self.assertEqual(self.estimate()["boot"]["status"],"STATIC_MINIMUM_EXCEEDS")

    def test_unknown_placement(self):
        self.files["userdata.img"]={"bytes":4096}
        with self.assertRaisesRegex(ValueError,"Unknown development storage path"):
            self.estimate()


if __name__=="__main__":
    unittest.main()
