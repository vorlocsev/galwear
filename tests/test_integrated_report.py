"""Tests for read-only consolidated R800 reports; synthetic input only."""
from __future__ import annotations

from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "installer"))
sys.path.insert(0, str(ROOT / "tests"))

from test_installer_guard import fake_pit, synthetic_archive
from test_recovery_audit import build_archives
from r800_preflight_report import inspect_files, main
from r800_safety import SafetyError


class IntegratedReportTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        self.package = self.dir / "R800-WearOS.tar.md5"
        self.pit = self.dir / "r800.pit"
        synthetic_archive(self.package)
        self.pit.write_bytes(fake_pit())

    def test_valid_synthetic_inputs_report_without_authorization(self):
        report = inspect_files(self.package, self.pit)
        self.assertEqual(report["result"], "STRUCTURAL_PASS_ONLY")
        self.assertEqual(report["partition_count_checked"], 12)
        self.assertEqual(len(report["images"]), 12)
        for field in ("flashing_safe", "device_model_verified",
                      "bootloader_signature_verified", "hardware_tested"):
            self.assertFalse(report[field])

    def test_wrong_partition_id_rejected(self):
        self.pit.write_bytes(fake_pit(overrides={"dzImage": 99}))
        with self.assertRaises(SafetyError):
            inspect_files(self.package, self.pit)

    def test_missing_partition_rejected(self):
        self.pit.write_bytes(fake_pit(omit=("dzImage",)))
        with self.assertRaises(SafetyError):
            inspect_files(self.package, self.pit)

    def test_truncated_pit_rejected(self):
        self.pit.write_bytes(fake_pit()[:-1])
        with self.assertRaises(SafetyError):
            inspect_files(self.package, self.pit)

    def test_oversized_pit_rejected(self):
        self.pit.write_bytes(b"x" * (64 * 1024 + 1))
        with self.assertRaises(SafetyError):
            inspect_files(self.package, self.pit)

    def test_empty_pit_rejected(self):
        self.pit.write_bytes(b"")
        with self.assertRaises(SafetyError):
            inspect_files(self.package, self.pit)

    def test_bad_archive_rejected(self):
        synthetic_archive(self.package, invalid_md5=True)
        with self.assertRaises(SafetyError):
            inspect_files(self.package, self.pit)

    def test_cli_report_writes_json(self):
        path = self.dir / "report.json"
        status = main(["--package", str(self.package),
                       "--pit-file", str(self.pit), "--output", str(path)])
        self.assertEqual(status, 0)
        self.assertIn('"flashing_safe": false', path.read_text(encoding="utf-8"))

    def test_cli_failure_writes_rejected_json(self):
        self.pit.write_bytes(b"")
        path = self.dir / "rejected.json"
        status = main(["--package", str(self.package),
                       "--pit-file", str(self.pit), "--output", str(path)])
        self.assertEqual(status, 2)
        self.assertIn('"result": "REJECT"', path.read_text(encoding="utf-8"))

    def test_reference_archive_match_synthetic(self):
        package, combination = build_archives(self.dir)
        report = inspect_files(package, self.pit, combination)
        ref = report["reference_comparison"]
        self.assertTrue(ref["reference_matches"])
        self.assertEqual(ref["matching_reference_members"], 8)
        self.assertFalse(ref["source_authenticity_verified"])

    def test_reference_archive_mismatch_rejected(self):
        package, combination = build_archives(
            self.dir, altered={"sboot.bin": b"changed"})
        with self.assertRaisesRegex(SafetyError, "sboot.bin differs"):
            inspect_files(package, self.pit, combination)

    def test_module_contains_no_network_import(self):
        source = (ROOT / "installer" / "r800_preflight_report.py").read_text()
        self.assertNotIn("import socket", source)
        self.assertNotIn("flash_ap_package(", source)


if __name__ == "__main__":
    unittest.main()
