"""Regression checks for PHH extraction comparison."""
from copy import deepcopy
from pathlib import Path
import sys
import unittest

BUILD = str(Path(__file__).resolve().parents[1] / "build")
if BUILD not in sys.path:
    sys.path.insert(0, BUILD)
from r800_phh_extraction_comparison import compare, phh


class PhhExtractionComparisonTests(unittest.TestCase):
    sha = "a" * 40

    def setUp(self):
        self.first = {
            "source_sha": self.sha, "status": "PHH_V313_ARM32_RUNTIME_STATIC_ONLY",
            "release_id": phh.RELEASE_ID, "asset_id": phh.ASSET_ID,
            "asset_name": phh.ASSET_NAME, "asset_bytes": phh.ASSET_SIZE,
            "source": phh.SOURCE, "asset_sha256_observed": phh.OBSERVED_ASSET_SHA256,
            "system_sha256": phh.OBSERVED_SYSTEM_SHA256, "system_bytes": phh.OBSERVED_SYSTEM_BYTES,
            "first_observation_pin_matched": True, "runtime_observation_pins_matched": True,
            "independent_asset_sha256_verified": False, "wear_os_donor": False,
            "runtime_executed": False, "safe_to_flash": False,
            "runtime": {
                "status": "ARM32_BIONIC_RUNTIME_EXTRACTED_STATIC_ONLY",
                "system_sha256": phh.OBSERVED_SYSTEM_SHA256,
                "raw_system_sha256": phh.OBSERVED_RAW_SYSTEM_SHA256,
                "apex_sha256": phh.OBSERVED_APEX_SHA256,
                "apex_payload_sha256": phh.OBSERVED_APEX_PAYLOAD_SHA256,
                "files": {name: {"sha256": digest} for name, digest in phh.OBSERVED_RUNTIME_SHA256.items()},
                **dict.fromkeys(("runtime_authenticity_verified", "android_version_verified",
                                 "apex_signature_verified", "runtime_stub_exclusion_proven",
                                 "runtime_verified", "safe_to_flash"), False),
            },
        }
        self.second = deepcopy(self.first)

    def audit(self, status="REVIEW_REQUIRED"):
        result = compare(self.first, self.second, self.sha)
        self.assertEqual(result["status"], status)
        for flag in ("wear_os_donor", "independent_asset_sha256_verified",
                     "runtime_verified", "hardware_tested", "safe_to_flash"):
            self.assertIs(result[flag], False)
        return result

    def test_matching_reports(self):
        self.assertFalse(self.audit("PHH_REFERENCE_EXTRACTION_REPORTS_MATCH")["errors"])

    def test_stale_sha(self):
        self.second["source_sha"] = "b"*40
        self.audit()

    def test_asset_identity_mismatch(self):
        self.second["asset_id"] += 1
        self.audit()

    def test_compressed_digest_mismatch(self):
        self.second["asset_sha256_observed"] = "b"*64
        self.audit()

    def test_runtime_digest_mismatch(self):
        self.second["runtime"]["files"]["libc.so"]["sha256"] = "b"*64
        self.audit()

    def test_same_wrong_runtime_pins(self):
        for report in (self.first, self.second):
            report["runtime"]["apex_sha256"] = "b"*64
        self.audit()

    def test_metadata_difference(self):
        self.second["runtime"]["files"]["libc.so"]["guest_path"] = "/wrong"
        self.audit()

    def test_wear_os_promotion_rejected(self):
        self.second["wear_os_donor"] = True
        self.audit()

    def test_missing_apex_signature_hold(self):
        del self.second["runtime"]["apex_signature_verified"]
        self.audit()

    def test_bad_sha(self):
        with self.assertRaises(ValueError):
            compare(self.first, self.second, "short")


if __name__ == "__main__":
    unittest.main()
