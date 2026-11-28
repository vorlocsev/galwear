"""Test the offline graphics acceptance gate and non-release boundaries."""
from pathlib import Path
import sys
import unittest

BUILD = str(Path(__file__).resolve().parents[1] / "build")
if BUILD not in sys.path:
    sys.path.insert(0, BUILD)
from r800_graphics_acceptance import (
    ABI_HOLDS, FIXTURE_HOLDS, HWC_FLAGS, EGL_FLAGS, LIBHARDWARE, SYSTEM_CORE, combine, expressions,
    DONOR_CHECKS, BINDING_HOLDS,
)


class GraphicsAcceptanceTests(unittest.TestCase):
    sha = "a" * 40

    def setUp(self):
        layout = dict.fromkeys(expressions(), 0)
        layout["hwc_layer_1_t.size"] = 96
        self.abi = dict.fromkeys(ABI_HOLDS, False)
        self.abi.update(source_sha=self.sha, status="AOSP11_LEGACY_GRAPHICS_LAYOUT_ONLY",
                        aosp_libhardware_commit=LIBHARDWARE, aosp_system_core_commit=SYSTEM_CORE,
                        fields_per_abi=97,
                        layouts={arch: {"aosp": dict(layout, pointer_bytes=pointer),
                                        "local": dict(layout, pointer_bytes=pointer), "differences": {}}
                                 for arch, pointer in (("arm", 4), ("arm64", 8))})
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

    def bind_donor(self):
        tree = {"algorithm": "sha256-ordered-tree-records-v1", "sha256": "c"*64,
                "entries": 300, "regular_bytes": 10000}
        self.donor.update(source_sha=self.sha, status="STATIC_GRAPHICS_DEPENDENCY_CANDIDATES_ONLY",
                          donor_binding={"schema": "galwear-r800-extracted-donor-binding-v1",
                                         "source_sha": self.sha, "tree_before": tree.copy(),
                                         "tree_after": tree.copy(), "config_sha256": "d"*64,
                                         "dtb_sha256": "e"*64, "tracked_checkout_clean": True,
                                         "tree_unchanged_observed": True,
                                         **dict.fromkeys(BINDING_HOLDS, False)})
        self.donor["donor_preflight"].update(checks=dict.fromkeys(DONOR_CHECKS, True),
                                             release_status="HOLD_HARDWARE_UNVERIFIED")
        return self.donor["donor_binding"]

    def test_bound_donor_static_only(self):
        self.bind_donor()
        result = self.audit("OFFLINE_GRAPHICS_EVIDENCE_ONLY", self.donor)
        self.assertEqual(result["donor"]["status"], "BOUND_STATIC_PREREQUISITES_ONLY")
        self.assertIs(result["donor"]["source_sha_bound"], True)
        self.assertIs(result["donor"]["input_provenance_verified"], False)
        self.assertIs(result["donor"]["static_prerequisites_complete"], True)

    def test_bound_incomplete_donor(self):
        self.bind_donor()
        p = self.donor["donor_preflight"]
        p["checks"]["mapper_factory_export"] = False
        p["missing_static_prerequisites"] = ["mapper_factory_export"]
        p["status"] = "REVIEW_REQUIRED"
        result = self.audit("OFFLINE_GRAPHICS_EVIDENCE_ONLY", self.donor)
        self.assertEqual(result["donor"]["status"], "BOUND_STATIC_REPORT_REVIEW_REQUIRED")
        self.assertFalse(result["donor"]["static_prerequisites_complete"])

    def test_bound_donor_stale_sha(self):
        self.bind_donor()["source_sha"] = "b"*40
        self.audit(donor=self.donor)

    def test_bound_donor_stale_report_sha(self):
        self.bind_donor()
        self.donor["source_sha"] = "b"*40
        self.audit(donor=self.donor)

    def test_bound_donor_tree_changed(self):
        self.bind_donor()["tree_after"]["sha256"] = "f"*64
        self.audit(donor=self.donor)

    def test_bound_donor_malformed_tree(self):
        b = self.bind_donor()
        b["tree_before"]["entries"] = b["tree_after"]["entries"] = True
        self.audit(donor=self.donor)

    def test_bound_donor_missing_kernel_digest(self):
        self.bind_donor()["dtb_sha256"] = None
        self.audit(donor=self.donor)

    def test_bound_donor_image_authenticity_not_inferred(self):
        self.bind_donor()["original_image_authenticity_verified"] = True
        self.audit(donor=self.donor)

    def test_bound_donor_missing_check(self):
        self.bind_donor()
        del self.donor["donor_preflight"]["checks"]["egl_candidates"]
        self.audit(donor=self.donor)

    def test_bound_donor_inconsistent_failures(self):
        self.bind_donor()
        self.donor["donor_preflight"]["checks"]["mapper_factory_export"] = False
        self.audit(donor=self.donor)

    def test_bound_donor_inconsistent_graph_status(self):
        self.bind_donor()
        self.donor["status"] = "REVIEW_REQUIRED"
        self.audit(donor=self.donor)

    def test_bound_donor_malformed_binding(self):
        self.bind_donor()
        self.donor["donor_binding"] = []
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
        self.abi["layouts"]["arm64"]["local"]["pointer_bytes"] = 100
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

    def test_wrong_difference_container(self):
        self.abi["layouts"]["arm"]["differences"] = []
        self.audit()

    def test_equal_but_wrong_architecture(self):
        for section in ("aosp", "local"):
            self.abi["layouts"]["arm64"][section]["pointer_bytes"] = 4
        self.audit()

    def test_equal_but_wrong_field_names(self):
        for section in ("aosp", "local"):
            layout = self.abi["layouts"]["arm"][section]
            layout["not_an_abi_field"] = layout.pop("pointer_bytes")
        self.audit()

    def test_invalid_sha(self):
        with self.assertRaises(ValueError):
            combine(self.abi, self.fixture, "short")


if __name__ == "__main__":
    unittest.main()
