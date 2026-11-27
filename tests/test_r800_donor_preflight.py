"""Donor intake tests use only synthetic files."""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "build"))
from r800_donor_preflight import audit, verify_components, digest, system

SHA = "a" * 40

class DonorPreflightTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        self.donors = root / "donors"
        self.components = root / "components"
        self.donors.mkdir()
        self.components.mkdir()
        self.item = self.components / "example"
        self.item.write_bytes(b"synthetic")
        info = {"bytes": 9, "sha256": hashlib.sha256(b"synthetic").hexdigest(),
                "mode": oct(self.item.stat().st_mode & 0o777)}
        manifest = {"status": "PARTIAL_COMPILED_COMPONENTS_ONLY", "source_sha": SHA,
                    "safe_to_flash": False, "files": {"example": info}}
        (self.components / "component-evidence.json").write_text(json.dumps(manifest))

    def test_reports_all_missing(self):
        report = audit(self.donors, self.components, SHA)
        self.assertEqual(report["status"], "DONOR_INPUTS_INCOMPLETE")
        self.assertEqual(report["inputs"]["compiled-components"]["status"], "STRUCTURE_PASS_ONLY")
        self.assertIn("samsung/combination.tar.md5", report["blockers"])
        self.assertIn("android/system", report["blockers"])
        for name, row in report["inputs"].items():
            if name != "compiled-components":
                self.assertEqual(row["status"], "MISSING", name)
        self.assertFalse(report["safe_to_flash"])

    def test_existing_curated_directory_is_distinct_from_missing(self):
        payload = self.donors / "payload"
        payload.mkdir()
        (payload / "lib").mkdir()
        (payload / "tzlite").write_bytes(b"not a directory")
        report = audit(self.donors, self.components, SHA)
        for name in ("payload/lib", "payload/tzlite"):
            self.assertEqual(report["inputs"][name]["status"], "REJECTED")
            self.assertIn(name, report["blockers"])
        (payload / "lib" / "fixture").write_bytes(b"synthetic")
        report = audit(self.donors, self.components, SHA)
        self.assertEqual(report["inputs"]["payload/lib"]["status"], "STRUCTURE_PASS_ONLY")
        self.assertFalse(report["inputs"]["payload/lib"]["contents_verified"])
        self.assertFalse(report["safe_to_flash"])

    def test_dynamic_loader_is_required(self):
        report = audit(self.donors, self.components, SHA)
        self.assertIn("tizen/ld-linux.so.3", report["blockers"])

    def test_digest_and_header_same_bytes(self):
        path = self.donors / "system.img"
        raw = bytes(1080) + b"\x53\xef" + bytes(12)
        path.write_bytes(raw)
        expected = {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
        self.assertEqual(digest(path, header_bytes=1082), (expected, raw[:1082]))
        self.assertEqual(system(path), expected)

    def test_streaming_digest_rejects_symlink(self):
        path = self.donors / "alias"
        path.symlink_to(self.item)
        with self.assertRaises(ValueError):
            digest(path)

    def test_malformed_archive_reported(self):
        p = self.donors / "samsung/combination.tar.md5"
        p.parent.mkdir()
        p.write_bytes(b"bad archive")
        self.assertEqual(audit(self.donors, self.components, SHA)["inputs"]["samsung/combination.tar.md5"]["status"], "REJECTED")

    def test_component_changed(self):
        self.item.write_bytes(b"modified!")
        with self.assertRaisesRegex(ValueError, "hash mismatch"):
            verify_components(self.components, SHA)

    def test_wrong_source(self):
        with self.assertRaisesRegex(ValueError, "source SHA"):
            verify_components(self.components, "b" * 40)

    def test_unlisted_component(self):
        (self.components / "extra").write_bytes(b"extra")
        with self.assertRaisesRegex(ValueError, "inventory mismatch"):
            verify_components(self.components, SHA)

    def test_symlink_rejected(self):
        (self.components / "extra").symlink_to(self.item)
        with self.assertRaisesRegex(ValueError, "Symlink"):
            verify_components(self.components, SHA)

if __name__ == "__main__":
    unittest.main()
