"""Static HWC property hints must never prove the donor layer ABI."""
from pathlib import Path
import sys
import tempfile
import unittest

BUILD = str(Path(__file__).resolve().parents[1] / "build")
if BUILD not in sys.path:
    sys.path.insert(0, BUILD)
from r800_graphics_inventory import hwc_stride_evidence


class HwcStrideEvidenceTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)

    def write(self, path, contents):
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(contents, encoding="utf-8")

    def audit(self):
        r = hwc_stride_evidence(self.root)
        self.assertEqual(r["status"], "REVIEW_REQUIRED")
        self.assertEqual(r["historical_default_stride"], 100)
        self.assertEqual(r["aosp_arm32_layer_bytes"], 96)
        self.assertIsNone(r["runtime_effective_stride"])
        for field in ("donor_layer_layout_verified", "donor_layer_stride_100_verified",
                      "mapper_2_1_verified", "hardware_tested", "safe_to_flash"):
            self.assertIs(r[field], False)
        return r

    def test_no_property_does_not_confirm_default(self):
        r = self.audit()
        self.assertEqual(r["assignments"], [])
        self.assertIsNone(r["observed_explicit_stride"])
        self.assertFalse(r["conflicting_assignments"])

    def test_explicit_aosp_stride_is_only_a_hint(self):
        self.write("vendor/build.prop", "# comment\ndebug.r800.layer_stride=96\n")
        r = self.audit()
        self.assertEqual(r["observed_explicit_stride"], 96)
        self.assertEqual(r["assignments"], [
            {"source": "/vendor/build.prop", "line": 2, "value": "96"}])

    def test_explicit_donor_stride_is_only_a_hint(self):
        self.write("system/build.prop", "debug.r800.layer_stride=100\n")
        self.assertEqual(self.audit()["observed_explicit_stride"], 100)

    def test_conflicting_partitions_no_precedence_assumed(self):
        self.write("system/build.prop", "debug.r800.layer_stride=96\n")
        self.write("vendor/build.prop", "debug.r800.layer_stride=100\n")
        r = self.audit()
        self.assertTrue(r["conflicting_assignments"])
        self.assertIsNone(r["observed_explicit_stride"])

    def test_conflicting_lines_in_same_file(self):
        self.write("vendor/build.prop", "debug.r800.layer_stride=96\ndebug.r800.layer_stride=100\n")
        r = self.audit()
        self.assertTrue(r["conflicting_assignments"])
        self.assertEqual(len(r["assignments"]), 2)

    def test_repeated_equal_values_not_conflicting(self):
        self.write("system/build.prop", "debug.r800.layer_stride=96\n")
        self.write("vendor/build.prop", "debug.r800.layer_stride=96\n")
        r = self.audit()
        self.assertEqual(r["observed_explicit_stride"], 96)
        self.assertFalse(r["conflicting_assignments"])
        self.assertEqual(len(r["assignments"]), 2)

    def test_invalid_values_rejected(self):
        for value in ("", "99", "096", "-100", "96 # comment"):
            with self.subTest(value=value):
                self.write("vendor/build.prop", "debug.r800.layer_stride=" + value + "\n")
                r = self.audit()
                self.assertIsNone(r["observed_explicit_stride"])
                self.assertTrue(r["errors"])

    def test_comments_and_unrelated_properties_ignored(self):
        self.write("system/build.prop", "# debug.r800.layer_stride=96\nother.stride=100\n")
        self.assertEqual(self.audit()["assignments"], [])

    def test_unreadable_encoding_requires_review(self):
        self.write("vendor/build.prop", "")
        (self.root / "vendor/build.prop").write_bytes(b"\xff")
        r = self.audit()
        self.assertTrue(r["errors"])
        self.assertIsNone(r["observed_explicit_stride"])


if __name__ == "__main__":
    unittest.main()
