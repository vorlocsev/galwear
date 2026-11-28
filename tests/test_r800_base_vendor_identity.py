"""Synthetic vendor reports; not evidence of a particular TicWatch model."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"build"))
import r800_base_vendor_identity as base

PIN="a"*64
EFFECTS="b"*64


class BaseVendorIdentityTests(unittest.TestCase):
    def setUp(self):
        self.props={
            "ro.product.vendor.brand":"fixture",
            "ro.product.vendor.manufacturer":"fixture",
            "ro.product.vendor.model":"fixture watch",
            "ro.product.vendor.device":"fixture",
            "ro.vendor.build.id":"FIXTURE",
            "ro.vendor.build.fingerprint":"fixture/product/fixture:9/FIXTURE/1:user/release-keys",
            "ro.vendor.build.version.release":"9",
            "ro.vendor.build.version.sdk":"28",
            "ro.vndk.version":"28",
            "ro.product.vendor.cpu.abilist":"armeabi-v7a,armeabi"}
        self.report={"status":"EXT4_DONOR_EXTRACTION_ONLY","profile":"vendor-identity",
                     "image_sha256":PIN,"snapshot_verified":True,
                     "donor_compatibility_verified":False,"safe_to_flash":False,
                     "files":{"vendor/lib/libeffectsconfig.so":{"status":"EXTRACTED","sha256":EFFECTS}},
                     "missing_or_ambiguous":[],
                     "vendor_identity":{"properties":self.props,"property_conflicts":[],
                        "identity_inventory":base.identity_inventory(self.props,[]),
                        "hidl_groups":{n:{"inventory_complete":True,"missing":[],"elf_review":[]}
                                       for n in base.GROUPS},
                        "vintf":{"status":"DECLARATIONS_PRESENT"}}}

    def describe(self,pin=PIN,effects=EFFECTS):
        row=self.report["vendor_identity"]
        row["identity_inventory"]=base.identity_inventory(self.props,row["property_conflicts"])
        return base.describe(self.report,pin,effects)

    def test_literal_identity(self):
        result=self.describe()
        self.assertEqual(result["status"],"BASE_VENDOR_IDENTITY_FIELDS_OBSERVED_ONLY")
        self.assertEqual(result["observed_identity"]["model"],"fixture watch")
        self.assertFalse(result["historical_donor_match_verified"])
        self.assertFalse(result["safe_to_flash"])

    def test_effects_match(self):
        self.assertEqual(self.describe()["effects_base_comparison"],"MATCHES_BASE_MEMBER")
        self.assertEqual(self.describe(effects="c"*64)["effects_base_comparison"],"DIFFERS_FROM_BASE_MEMBER")
        self.assertEqual(self.describe(effects=None)["effects_base_comparison"],"NOT_SUPPLIED")

    def test_missing_effects(self):
        self.report["files"]={}
        self.assertEqual(self.describe()["effects_base_comparison"],"NOT_IN_SELECTED_BASE")

    def test_missing_model(self):
        del self.props["ro.product.vendor.model"]
        self.assertEqual(self.describe()["status"],"REVIEW_REQUIRED")

    def test_fingerprint_mismatch(self):
        self.props["ro.vendor.build.id"]="OTHER"
        self.assertEqual(self.describe()["status"],"REVIEW_REQUIRED")

    def test_abi_not_established(self):
        self.props["ro.product.vendor.cpu.abilist"]="arm64-v8a"
        self.assertEqual(self.describe()["status"],"REVIEW_REQUIRED")

    def test_conflicting_model(self):
        self.report["vendor_identity"]["property_conflicts"]=["ro.product.vendor.model"]
        result=self.describe()
        self.assertIsNone(result["observed_identity"]["model"])
        self.assertEqual(result["status"],"REVIEW_REQUIRED")

    def test_wrong_image(self):
        with self.assertRaisesRegex(ValueError,"Unexpected base vendor extraction scope"):
            self.describe(pin="0"*64)

    def test_changed_inventory(self):
        self.report["vendor_identity"]["identity_inventory"]["status"]="REVIEW_REQUIRED"
        with self.assertRaisesRegex(ValueError,"Vendor identity inventory mismatch"):
            base.describe(self.report,PIN)


if __name__=="__main__":
    unittest.main()
