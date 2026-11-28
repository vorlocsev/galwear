"""Regression checks for same-head synthetic graphics evidence gate."""
from pathlib import Path
import sys
import unittest

BUILD = str(Path(__file__).resolve().parents[1] / "build")
if BUILD not in sys.path:
    sys.path.insert(0, BUILD)
from r800_graphics_fixture_summary import (
    HWC_FLAGS, EGL_FLAGS, HWC_HOLDS, EGL_HOLDS, HWC_MARKERS, summarize,
)


class GraphicsFixtureSummaryTests(unittest.TestCase):
    sha = "a" * 40

    def setUp(self):
        self.hwc = dict.fromkeys(HWC_FLAGS, True)
        self.hwc.update(dict.fromkeys(HWC_HOLDS, False))
        self.hwc.update(source_sha=self.sha, status="ARM32_HWC_SYNTHETIC_FB_LIFECYCLE_ONLY",
                        hwc_fixture_requested=True,
                        results={"hwcomposer.r800.so": {
                            "status": "HWC_FIXTURE_PASS", "exit_code": 0,
                            "log": "\n".join(HWC_MARKERS)}})
        self.egl = dict.fromkeys(EGL_FLAGS, True)
        self.egl.update(dict.fromkeys(EGL_HOLDS, False))
        self.egl.update(source_sha=self.sha, status="ARM32_SYNTHETIC_EGL_LINK_ONLY")

    def audit(self, expected="REVIEW_REQUIRED"):
        result = summarize(self.hwc, self.egl, self.sha)
        self.assertEqual(result["status"], expected)
        for key in ("donor_surfaceflinger_verified", "donor_mapper_verified",
                    "donor_mali_verified", "real_sync_file_verified",
                    "hardware_tested", "android_boot_tested", "safe_to_flash"):
            self.assertIs(result[key], False)
        self.assertEqual(result["release_status"], "HOLD_HARDWARE_UNVERIFIED")
        return result

    def test_complete_synthetic_evidence_only(self):
        self.assertFalse(self.audit("SYNTHETIC_GRAPHICS_PIPELINE_ONLY")["errors"])

    def test_stale_sha(self):
        self.egl["source_sha"] = "b" * 40
        self.audit()

    def test_missing_positive(self):
        del self.hwc[HWC_FLAGS[0]]
        self.audit()

    def test_non_boolean_positive(self):
        self.egl[EGL_FLAGS[0]] = 1
        self.audit()

    def test_hardware_promotion_rejected(self):
        self.hwc["hardware_tested"] = True
        self.audit()

    def test_missing_hold(self):
        del self.egl["safe_to_flash"]
        self.audit()

    def test_wrong_evidence_status(self):
        self.hwc["status"] = "HMI_ONLY_PASS"
        self.audit()

    def test_missing_marker(self):
        self.hwc["results"]["hwcomposer.r800.so"]["log"] = "\n".join(HWC_MARKERS[1:])
        self.audit()

    def test_duplicate_marker(self):
        self.hwc["results"]["hwcomposer.r800.so"]["log"] += "\n" + HWC_MARKERS[0]
        self.audit()

    def test_failed_hwc_exit(self):
        self.hwc["results"]["hwcomposer.r800.so"]["exit_code"] = 1
        self.audit()

    def test_short_sha_rejected(self):
        with self.assertRaises(ValueError):
            summarize(self.hwc, self.egl, self.sha[:7])

    def test_extra_result_rejected(self):
        self.hwc["results"]["unexpected.so"] = {}
        self.audit()


if __name__ == "__main__":
    unittest.main()
