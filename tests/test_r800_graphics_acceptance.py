"""Test the offline graphics acceptance gate and non-release boundaries."""
from pathlib import Path
import sys
import unittest

BUILD = str(Path(__file__).resolve().parents[1] / "build")
if BUILD not in sys.path:
    sys.path.insert(0, BUILD)
from r800_graphics_acceptance import (
    ABI_HOLDS, FIXTURE_HOLDS, HWC_FLAGS, EGL_FLAGS, LIBHARDWARE, SYSTEM_CORE, combine,
)


class GraphicsAcceptanceTests(unittest.TestCase):
    sha = "a" * 40

    def setUp(self):
        layout = {"hwc_layer_1_t.size": 96, **{"field" + str(i): i for i in range(96)}}
        self.abi = dict.fromkeys(ABI_HOLDS, False)
        self.abi.update(source_sha=self.sha, status="AOSP11_LEGACY_GRAPHICS_LAYOUT_ONLY",
                        aosp_libhardware_commit=LIBHARDWARE, aosp_system_core_commit=SYSTEM_CORE,
                        fields_per_abi=97,
                        layouts={arch: {"aosp": layout.copy(), "local": layout.copy(), "differences": []}
                                 for arch in ("arm", "arm64")})
        self.fixture = dict.fromkeys(FIXTURE_HOLDS, False)
        self.fixture.update(source_sha=self.sha, status="SYNTHETIC_GRAPHICS_PIPELINE_ONLY",
                            schema="galwear-r800-graphics-fixture-summary-v1", errors=[],
                            release_status="HOLD_HARDWARE_UNVERIFIED",
                            hwc_flags=dict.fromkeys(HWC_FLAGS, True), egl_flags=dict.fromkeys(EGL_FLAGS, True))
        self.donor = {"safe_to_flash": False, "donor_preflight": {
            **dict.fromkeys(("donor_surfaceflinger_verified", "donor_mapper_verified",
                              "donor_mali_verified", "hardware_tested", "safe_to_flash"), False),
            "status": "STATIC_DONOR_PREREQUISITES_ONLY", "checks": {"example": True},
            "missing_static_prerequisites": [], "runtime_blockers": ["runtime unverified"]}}

    def audit(self, expected="REVIEW_REQUIRED", donor=None):
        result = combine(self.abi, self.fixture, self.sha, donor)
        self.assertEqual(result["status"], expected)
        for key in FIXTURE_HOLDS:
            self.assertIs(result[key], False)
        self.assertEqual(result["release_status"], "HOLD_HARDWARE_UNVERIFIED")
        return result

    def test_no_donor_is_explicit(self):
        result = self.audit("OFFLINE_GRAPHICS_EVIDENCE_ONLY")
        self.assertEqual(result["donor"]["status"], "NOT_PROVIDED")

    def test_unbound_donor_never_promoted(self):
        result = self.audit("OFFLINE_GRAPHICS_EVIDENCE_ONLY", self.donor)
        self.assertEqual(result["donor"]["status"], "UNBOUND_STATIC_REPORT_REVIEW_REQUIRED")
        self.assertFalse(result["donor"]["source_sha_bound"])
        self.assertFalse(result["donor"]["static_prerequisites_complete"])

    def test_donor_hardware_promotion_rejected(self):
        self.donor["donor_preflight"]["hardware_tested"] = True
        self.audit(donor=self.donor)

    def test_stale_fixture(self):
        self.fixture["source_sha"] = "b" * 40
        self.audit()

    def test_stale_abi(self):
        self.abi["source_sha"] = "b" * 40
        self.audit()

    def test_pin_mismatch(self):
        self.abi["aosp_libhardware_commit"] = "b" * 40
        self.audit()

    def test_layout_difference(self):
        self.abi["layouts"]["arm64"]["local"]["field0"] = 100
        self.audit()

    def test_truncated_layout(self):
        self.abi["fields_per_abi"] = 96
        self.audit()

    def test_missing_fixture_flag(self):
        del self.fixture["hwc_flags"][HWC_FLAGS[0]]
        self.audit()

    def test_hardware_hold_missing(self):
        del self.abi["safe_to_flash"]
        self.audit()

    def test_wrong_fixture_schema(self):
        self.fixture["schema"] = "other"
        self.audit()

    def test_invalid_sha(self):
        with self.assertRaises(ValueError):
            combine(self.abi, self.fixture, "short")


if __name__ == "__main__":
    unittest.main()
