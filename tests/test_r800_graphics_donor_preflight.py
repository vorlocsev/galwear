"""Static donor graphics prerequisites must not certify runtime readiness."""
from pathlib import Path
import sys
import unittest

BUILD = str(Path(__file__).resolve().parents[1] / "build")
if BUILD not in sys.path:
    sys.path.insert(0, BUILD)
from r800_android_linker_audit import graphics_donor_preflight


class GraphicsDonorPreflightTests(unittest.TestCase):
    def setUp(self):
        path = "/system/bin/surfaceflinger"
        self.report = {
            "status": "STATIC_GRAPHICS_DEPENDENCY_CANDIDATES_ONLY",
            "roots": [path],
            "inventory": {
                "surfaceflinger_abi": "arm",
                "services": [{"name": "surfaceflinger", "path": path, "elf": {"architecture": "arm"}}],
                "egl_driver_groups": {"status": "STATIC_EGL_DRIVER_GROUP_ONLY"},
                "entrypoint_evidence": {"status": "STATIC_GRAPHICS_MINIMUM_EXPORTS_ONLY"},
                "mapper_2_1_evidence": {"status": "STATIC_MAPPER_2_1_CANDIDATES_ONLY"},
                "mapper_factory_evidence": {"status": "STATIC_MAPPER_FACTORY_EXPORT_ONLY"},
                "mali_evidence": {"status": "STATIC_MALI_RECIPE_EVIDENCE_ONLY"},
                "hwc_stride_evidence": {"observed_explicit_stride": 96,
                                        "errors": [], "conflicting_assignments": False},
            },
            "graph": {"objects": {path: {"abi": "arm"}},
                      "vintf_inventory": {"status": "LITERAL_INVENTORY_ONLY"}},
        }

    def audit(self, expected="REVIEW_REQUIRED"):
        result = graphics_donor_preflight(self.report)
        self.assertEqual(result["status"], expected)
        for key in ("donor_surfaceflinger_verified", "donor_mapper_verified",
                    "donor_mali_verified", "hardware_tested",
                    "android_boot_tested", "safe_to_flash"):
            self.assertIs(result[key], False)
        self.assertEqual(result["release_status"], "HOLD_HARDWARE_UNVERIFIED")
        self.assertTrue(result["runtime_blockers"])
        return result

    def test_complete_static_prerequisites_only(self):
        self.assertEqual(self.audit("STATIC_DONOR_PREREQUISITES_ONLY")["missing_static_prerequisites"], [])

    def test_missing_root_graph(self):
        self.report["graph"] = None
        result = self.audit()
        self.assertIn("surfaceflinger_graph_root", result["missing_static_prerequisites"])

    def test_empty_report(self):
        self.report.clear()
        self.assertEqual(len(self.audit()["missing_static_prerequisites"]), 10)

    def test_surfaceflinger_missing_root(self):
        self.report["roots"].clear()
        self.assertIn("surfaceflinger_graph_root", self.audit()["missing_static_prerequisites"])

    def test_missing_mapper_factory(self):
        del self.report["inventory"]["mapper_factory_evidence"]
        self.assertIn("mapper_factory_export", self.audit()["missing_static_prerequisites"])

    def test_mali_recipe_not_confirmed(self):
        self.report["inventory"]["mali_evidence"]["status"] = "REVIEW_REQUIRED"
        self.assertIn("mali_recipe_candidates", self.audit()["missing_static_prerequisites"])

    def test_stride_conflict(self):
        self.report["inventory"]["hwc_stride_evidence"]["conflicting_assignments"] = True
        self.assertIn("hwc_explicit_stride_hint", self.audit()["missing_static_prerequisites"])

    def test_legacy_default_not_explicit_hint(self):
        self.report["inventory"]["hwc_stride_evidence"]["observed_explicit_stride"] = None
        self.assertIn("hwc_explicit_stride_hint", self.audit()["missing_static_prerequisites"])

    def test_vintf_missing(self):
        del self.report["graph"]["vintf_inventory"]
        self.assertIn("vintf_literal_inventory", self.audit()["missing_static_prerequisites"])

    def test_dependency_candidates_incomplete(self):
        self.report["status"] = "REVIEW_REQUIRED"
        self.assertIn("graphics_dependency_candidates", self.audit()["missing_static_prerequisites"])


if __name__ == "__main__":
    unittest.main()
