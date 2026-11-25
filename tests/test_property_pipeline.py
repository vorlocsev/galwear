"""Synthetic pipeline tests. No AOSP source, compiler or QEMU invocation."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/"build"))
import r800_property_pipeline as a

class PipelineTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)

    def test_stage_records_verified_evidence(self):
        p = a.Pipeline(self.root/"run", "build", "commit")
        report = p.out/"evidence.json"
        report.write_text('{"status":"STATIC","safe_to_flash":false}')
        with patch.object(a.subprocess, "run") as run:
            p.step("test", ["fake"], report, "STATIC")
        self.assertEqual(p.steps[0]["status"], "PASS")
        self.assertEqual(len(p.steps[0]["evidence_sha256"]), 64)
        self.assertTrue(run.call_args.kwargs["check"])
        self.assertFalse(a.read_report(p.out/"pipeline.json")["property_service_started"])

    def test_failed_process(self):
        p = a.Pipeline(self.root/"run", "boot")
        with patch.object(a.subprocess, "run", side_effect=subprocess.CalledProcessError(1, "fake")):
            with self.assertRaises(subprocess.CalledProcessError):
                p.step("failed", ["fake"])
        self.assertEqual(a.read_report(p.out/"pipeline.json")["status"], "REJECT")
        self.assertEqual(p.steps[0]["status"], "FAILED")

    def test_wrong_status(self):
        p = a.Pipeline(self.root/"run", "boot")
        report = p.out/"evidence.json"
        report.write_text('{"status":"REJECT","safe_to_flash":false}')
        with patch.object(a.subprocess, "run"):
            with self.assertRaisesRegex(ValueError, "Unexpected stage status"):
                p.step("wrong", ["fake"], report, "PASS")
        self.assertEqual(p.status, "REJECT")

    def test_no_overwrite(self):
        a.Pipeline(self.root/"run", "build")
        with self.assertRaises(FileExistsError):
            a.Pipeline(self.root/"run", "boot")

    def test_output_path_containment(self):
        b = self.root/"build"
        good = b/"aosp-out/target/product"
        good.mkdir(parents=True)
        path = b/"product-out-path.txt"
        path.write_text(str(good)+"\n")
        self.assertEqual(a.resolved_output(b, "product"), good)
        path.write_text(str(self.root)+"\n")
        with self.assertRaisesRegex(ValueError, "escapes"):
            a.resolved_output(b, "product")

    def test_incomplete_build_rejected(self):
        p = a.Pipeline(self.root/"run", "build", "commit")
        p.status = "AOSP_PROPERTY_PIPELINE_BUILD_ONLY"
        p.save()
        with self.assertRaisesRegex(ValueError, "Incomplete"):
            a.verify_build(p.out, "commit")
        with self.assertRaisesRegex(ValueError, "source commit"):
            a.verify_build(p.out, "different")

    def test_reject_unsafe_report(self):
        p = self.root/"report.json"
        p.write_text('{"status":"STATIC","safe_to_flash":true}')
        with self.assertRaisesRegex(ValueError, "Unexpected stage status"):
            a.require_report(p, "STATIC")

    def test_duplicate_report_keys(self):
        p = self.root/"report.json"
        p.write_text('{"status":"REJECT","status":"STATIC"}')
        with self.assertRaises(ValueError):
            a.read_report(p)

if __name__ == "__main__":
    unittest.main()
