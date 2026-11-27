"""Synthetic staged-tree integrity checks; never execute guest code."""
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/"build"))
from r800_stage_tizen import stage
from r800_verify_tizen_stage import verify, MANIFEST
from test_android_linker_audit import fixture


class VerifyTizenStageTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        base = Path(tmp.name)
        donor = base / "donor"
        (donor/"usr/bin").mkdir(parents=True)
        (donor/"usr/lib").mkdir()
        (donor/"usr/bin/lhd").write_bytes(fixture("arm", needed=["libx.so"]))
        (donor/"usr/lib/libx.so").write_bytes(fixture("arm"))
        (donor/"lib").symlink_to("/usr/lib")
        self.tree = base / "stage"
        self.expected = stage(donor, self.tree, ["/usr/bin/lhd"])
        self.library = self.tree/"usr/lib/libx.so"
        self.manifest = self.tree/MANIFEST

    def change_manifest(self, change):
        report = json.loads(self.manifest.read_text())
        change(report)
        self.manifest.write_text(json.dumps(report))

    def test_valid_tree(self):
        report = verify(self.tree, expected=self.expected)
        self.assertEqual(report["status"], "TIZEN_STAGED_TREE_STATIC_ONLY")
        self.assertTrue(report["manifest_matches_expected"])
        self.assertFalse(verify(self.tree)["manifest_matches_expected"])
        self.assertFalse(report["safe_to_flash"])

    def test_changed_bytes(self):
        raw = bytearray(self.library.read_bytes())
        raw[-1] ^= 1
        self.library.write_bytes(raw)
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            verify(self.tree)

    def test_extra_file(self):
        (self.library.parent/"extra.so").write_bytes(b"extra")
        with self.assertRaisesRegex(ValueError, "Unexpected file"):
            verify(self.tree)

    def test_missing_file(self):
        self.library.unlink()
        with self.assertRaisesRegex(ValueError, "does not match manifest"):
            verify(self.tree)

    def test_symlink(self):
        self.library.unlink()
        self.library.symlink_to("/usr/lib/libx.so")
        with self.assertRaisesRegex(ValueError, "Nonregular"):
            verify(self.tree)

    def test_hardlink(self):
        original = self.library.with_suffix(".original")
        self.library.rename(original)
        os.link(original, self.library)
        with self.assertRaisesRegex(ValueError, "hard link"):
            verify(self.tree)

    def test_mode_changed(self):
        self.library.chmod(0o777)
        with self.assertRaisesRegex(ValueError, "mode or link count mismatch"):
            verify(self.tree)

    def test_duplicate_manifest_key(self):
        self.manifest.write_text('{"files": {}, "files": {}}')
        with self.assertRaisesRegex(ValueError, "Duplicate manifest key"):
            verify(self.tree)

    def test_traversal(self):
        self.change_manifest(lambda r: r["files"].update(
            {"/usr/lib/../escape": r["files"]["/usr/lib/libx.so"]}))
        with self.assertRaisesRegex(ValueError, "Invalid manifest guest path"):
            verify(self.tree)

    def test_manifest_not_bound(self):
        self.change_manifest(lambda r: r.update(version_records_checked=1))
        with self.assertRaisesRegex(ValueError, "trusted staging result"):
            verify(self.tree, expected=self.expected)

    def test_forged_load_review(self):
        self.change_manifest(lambda r: r["files"]["/usr/lib/libx.so"]["load_review"].update(
            nonempty_load_count=99))
        with self.assertRaisesRegex(ValueError, "evidence mismatch|load review mismatch"):
            verify(self.tree)

    def test_false_readiness_claim(self):
        self.change_manifest(lambda r: r.update(safe_to_flash=True))
        with self.assertRaisesRegex(ValueError, "Invalid staging manifest"):
            verify(self.tree)


if __name__ == "__main__":
    unittest.main()
