"""Offline failure-path tests for the pinned AOSP graphics ABI evidence gate."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "r800_graphics_abi_under_test", ROOT / "build/r800_android_graphics_abi.py")
abi = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(abi)


class GraphicsAbiGateTests(unittest.TestCase):
    SHA = "a" * 40
    HEADER = "hardware/hwcomposer.h"
    RAW = b"synthetic pinned header\n"

    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.ndk = self.root / "ndk"
        self.ndk.mkdir()
        (self.ndk / "source.properties").write_text("Pkg.Revision = 27.2.12479018\n")
        self.output = self.root / "evidence"
        local = self.root / "src/hal/include" / self.HEADER
        local.parent.mkdir(parents=True)
        local.write_bytes(self.RAW)
        headers = {self.HEADER: ("hardware_libhardware", "b" * 40,
                                "include/hardware/hwcomposer.h", abi.git_blob(self.RAW))}
        for name, value in (("ROOT", self.root), ("HEADERS", headers)):
            p = patch.object(abi, name, value)
            p.start()
            self.addCleanup(p.stop)
        self.download = self.RAW
        self.difference = None
        self.wrong_pointer = False
        self.bad_arm_baseline = False
        p = patch.object(abi.subprocess, "run", side_effect=self.fake_download)
        self.curl = p.start()
        self.addCleanup(p.stop)
        p = patch.object(abi, "compile_layout", side_effect=self.fake_compile)
        self.compile = p.start()
        self.addCleanup(p.stop)

    def fake_download(self, args, **kwargs):
        self.assertEqual(args[0], "curl")
        Path(args[args.index("-o") + 1]).write_bytes(self.download)

    def fake_compile(self, cc, objcopy, include, work, name, expr):
        values = dict.fromkeys(expr, 0)
        is_arm = name.startswith("arm-")
        values["pointer_bytes"] = 4 if is_arm else 8
        values["hwc_layer_1_t.size"] = 96 if is_arm else 112
        values["hwc_display_contents_1_t.hwLayers"] = 20 if is_arm else 32
        if self.bad_arm_baseline and name == "arm-aosp":
            values["hwc_layer_1_t.size"] = 100
        if self.wrong_pointer and name == "arm64-local":
            values["pointer_bytes"] = 4
        if self.difference and name == self.difference:
            values["hwc_layer_1_t.size"] += 4
        return values

    def run_gate(self, sha=None):
        with contextlib.redirect_stdout(io.StringIO()):
            abi.run(self.ndk, self.output, self.SHA if sha is None else sha)

    def report(self):
        return json.loads((self.output / "graphics-abi-evidence.json").read_text())

    def assert_hold(self, report):
        for field in ("donor_layer_stride_100_verified", "mapper_2_1_verified",
                      "donor_runtime_verified", "hardware_tested", "safe_to_flash"):
            self.assertIs(report[field], False, field)

    def test_matching_abi_remains_layout_only(self):
        self.run_gate()
        r = self.report()
        self.assertEqual(r["status"], "AOSP11_LEGACY_GRAPHICS_LAYOUT_ONLY")
        self.assertEqual(r["source_sha"], self.SHA)
        self.assertEqual(r["fields_per_abi"], len(abi.expressions()))
        self.assertEqual(set(r["layouts"]), {"arm", "arm64"})
        self.assertEqual(self.compile.call_count, 4)
        self.assertTrue(r["header_provenance"][self.HEADER]["identical"])
        self.assert_hold(r)

    def test_arm32_donor_stride_difference_requires_review(self):
        self.difference = "arm-local"
        with self.assertRaisesRegex(ValueError, "layout mismatch"):
            self.run_gate()
        r = self.report()
        self.assertEqual(r["status"], "REVIEW_REQUIRED")
        self.assertEqual(r["layouts"]["arm"]["differences"]["hwc_layer_1_t.size"],
                         {"aosp": 96, "local": 100})
        self.assert_hold(r)

    def test_arm64_difference_also_requires_review(self):
        self.difference = "arm64-local"
        with self.assertRaisesRegex(ValueError, "layout mismatch"):
            self.run_gate()
        r = self.report()
        self.assertEqual(r["layouts"]["arm"]["differences"], {})
        self.assertIn("hwc_layer_1_t.size", r["layouts"]["arm64"]["differences"])
        self.assertEqual(r["status"], "REVIEW_REQUIRED")
        self.assert_hold(r)

    def test_tampered_pinned_header_never_reaches_compiler(self):
        self.download = b"modified"
        with self.assertRaisesRegex(ValueError, "Pinned AOSP blob mismatch"):
            self.run_gate()
        self.compile.assert_not_called()
        self.assertFalse((self.output / "graphics-abi-evidence.json").exists())

    def test_wrong_target_pointer_size_is_rejected(self):
        self.wrong_pointer = True
        with self.assertRaisesRegex(ValueError, "Wrong target pointer size"):
            self.run_gate()
        self.assertFalse((self.output / "graphics-abi-evidence.json").exists())

    def test_unexpected_aosp_arm32_baseline_is_rejected(self):
        self.bad_arm_baseline = True
        with self.assertRaisesRegex(ValueError, "Unexpected AOSP HWC ARM32 layout"):
            self.run_gate()
        self.assertFalse((self.output / "graphics-abi-evidence.json").exists())

    def test_unpinned_ndk_is_rejected_before_download(self):
        (self.ndk / "source.properties").write_text("Pkg.Revision = 28.0.0\n")
        with self.assertRaisesRegex(ValueError, "Expected NDK r27c"):
            self.run_gate()
        self.curl.assert_not_called()
        self.assertFalse(self.output.exists())

    def test_short_sha_is_rejected_before_download(self):
        with self.assertRaisesRegex(ValueError, "Exact source SHA required"):
            self.run_gate("a" * 7)
        self.curl.assert_not_called()

    def test_existing_output_cannot_be_overwritten(self):
        self.output.mkdir()
        marker = self.output / "graphics-abi-evidence.json"
        marker.write_text("prior evidence")
        with self.assertRaises(FileExistsError):
            self.run_gate()
        self.assertEqual(marker.read_text(), "prior evidence")
        self.curl.assert_not_called()


if __name__ == "__main__":
    unittest.main()
