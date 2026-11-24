"""Synthetic evidence tests; no device, network or firmware."""
import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "build"))
import r800_apk_inventory as audit

SHA = "a" * 40


class InventoryTests(unittest.TestCase):
    def setUp(self):
        self.a = audit.snapshot("clang19-19.1.4-r0\nmake-4.4.1-r2\n", SHA, 123, 1, "a")
        self.b = audit.snapshot("make-4.4.1-r2\nclang19-19.1.4-r0\n", SHA, 123, 1, "b")
        self.ia = dict(audit.identity(SHA, 123, 1, "a"), schema="galwear-r800-image-repeatability-v1",
                       status="ONE_BUILD_EVIDENCE_ONLY", safe_to_flash=False)
        self.ib = dict(self.ia, runner_replica="b")

    def compare(self):
        return audit.compare(self.a, self.b, self.ia, self.ib, SHA, 123, 1)

    def test_order_independent_match(self):
        self.assertEqual(self.compare()["status"], "APK_VERSIONS_MATCH")
        self.assertFalse(self.compare()["packages_fully_pinned"])

    def test_version_drift(self):
        self.b = audit.snapshot("make-4.4.1-r3\nclang19-19.1.4-r0\n", SHA, 123, 1, "b")
        out = self.compare()
        self.assertEqual(out["status"], "REJECT_PACKAGE_DRIFT")
        self.assertEqual(out["only_b"], ["make-4.4.1-r3"])

    def test_empty_duplicate_invalid(self):
        for text in ("", "a\na\n", "a b\n", "\n"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                audit.canonical(text)

    def test_digest_tamper(self):
        self.b["package_versions_sha256"] = "0" * 64
        with self.assertRaises(ValueError):
            self.compare()

    def test_wrong_image_identity(self):
        for field, value in (("galwear_commit", "b" * 40), ("run_id", 124),
                             ("run_attempt", 2), ("runner_replica", "a")):
            with self.subTest(field=field):
                original = copy.deepcopy(self.ib)
                self.ib[field] = value
                with self.assertRaises(ValueError):
                    self.compare()
                self.ib = original

    def test_wrong_inventory_identity(self):
        self.b["runner_replica"] = "a"
        with self.assertRaises(ValueError):
            self.compare()

    def test_missing_safety_flag(self):
        del self.b["safe_to_flash"]
        with self.assertRaises(ValueError):
            self.compare()

    def test_noncanonical_list(self):
        self.b["packages"].reverse()
        with self.assertRaises(ValueError):
            self.compare()


if __name__ == "__main__":
    unittest.main()
