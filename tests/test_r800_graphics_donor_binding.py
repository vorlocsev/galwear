"""Test donor tree fingerprinting without executing guest binaries."""
from pathlib import Path
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

BUILD = str(Path(__file__).resolve().parents[1] / "build")
if BUILD not in sys.path:
    sys.path.insert(0, BUILD)
import r800_graphics_donor_binding as binding


class GraphicsDonorBindingTests(unittest.TestCase):
    sha = "a" * 40

    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name) / "root"
        self.root.mkdir()
        (self.root / "vendor").mkdir()
        self.lib = self.root / "vendor" / "lib.so"
        self.lib.write_bytes(b"ELF-fixture")
        (self.root / "alias").symlink_to("vendor/lib.so")

    def test_stable_fingerprint(self):
        first = binding.snapshot(self.root)
        self.assertEqual(first, binding.snapshot(self.root))
        self.assertEqual(first["entries"], 3)
        self.assertEqual(first["regular_bytes"], 11)

    def test_changed_bytes(self):
        before = binding.snapshot(self.root)
        self.lib.write_bytes(b"new-fixture")
        self.assertNotEqual(before, binding.snapshot(self.root))

    def test_link_not_followed(self):
        outside = self.root.parent / "outside"
        outside.mkdir()
        (outside / "data").write_bytes(b"not in donor")
        (self.root / "external").symlink_to(outside, target_is_directory=True)
        before = binding.snapshot(self.root)
        (outside / "data").write_bytes(b"changed")
        self.assertEqual(before, binding.snapshot(self.root))

    def test_link_target_changes_digest(self):
        before = binding.snapshot(self.root)
        (self.root / "alias").unlink()
        (self.root / "alias").symlink_to("missing")
        self.assertNotEqual(before, binding.snapshot(self.root))

    def test_fifo_rejected_without_open(self):
        os.mkfifo(self.root / "fifo")
        with self.assertRaises(ValueError):
            binding.snapshot(self.root)

    def test_byte_budget(self):
        with patch.object(binding, "MAX_BYTES", 1), self.assertRaises(ValueError):
            binding.snapshot(self.root)

    def test_entry_budget(self):
        with patch.object(binding, "MAX_ENTRIES", 2), self.assertRaises(ValueError):
            binding.snapshot(self.root)

    def test_bound_audit_preserves_holds(self):
        with patch.object(binding, "checkout_sha", return_value=self.sha), \
             patch.object(binding, "audit_graphics_dependencies",
                          return_value={"safe_to_flash": False}):
            result = binding.bound_audit(self.root, self.sha)
        evidence = result["donor_binding"]
        self.assertEqual(evidence["source_sha"], self.sha)
        self.assertEqual(evidence["tree_before"], evidence["tree_after"])
        self.assertIs(evidence["tree_unchanged_observed"], True)
        for key in ("original_image_authenticity_verified", "extraction_provenance_verified",
                    "runtime_verified", "safe_to_flash"):
            self.assertIs(evidence[key], False)

    def test_mutation_during_audit_rejected(self):
        def mutate(*args):
            self.lib.write_bytes(b"changed")
            return {}
        with patch.object(binding, "checkout_sha", return_value=self.sha), \
             patch.object(binding, "audit_graphics_dependencies", side_effect=mutate), \
             self.assertRaisesRegex(ValueError, "changed during audit"):
            binding.bound_audit(self.root, self.sha)

    def test_short_sha_rejected(self):
        with self.assertRaises(ValueError):
            binding.checkout_sha("short")


if __name__ == "__main__":
    unittest.main()
