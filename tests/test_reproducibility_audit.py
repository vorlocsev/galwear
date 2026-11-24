"""Synthetic-only two-run evidence and digest comparator tests.

Does not compile any firmware or access a watch.
"""
from __future__ import annotations

from contextlib import redirect_stdout
import copy
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "build"))
import r800_reproducibility_audit as audit

BASE_SHA = "ab" * 20
IMAGE_ID = "sha256:" + "cd" * 32


class RepeatabilityTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.image = self.root / "Image"
        self.image.write_bytes(b"NON-RELEASE-IMAGE" * 100)
        self.patch = self.root / "kernel.patch"
        self.patch.write_text("fake source patch")
        self.config = self.root / ".config"
        self.config.write_text('CONFIG_INITRAMFS_SOURCE="/scratch/initramfs.list"\n')
        self.init = self.root / "init-evidence.json"
        self.cpio = self.root / "cpio-evidence.json"
        self.init_digest = hashlib.sha256(b"FAKE-ARM64-ELF").hexdigest()
        self.cpio_digest = hashlib.sha256(b"FAKE-NEWC").hexdigest()
        self.init.write_text(json.dumps({
            "status": "NON_RELEASE_INITRAMFS_SPEC_ONLY",
            "init": {"sha256": self.init_digest}}))
        self.cpio.write_text(json.dumps({
            "status": "SYNTHETIC_STRUCTURE_PASS_ONLY",
            "embedded_init_exact_match": True,
            "embedded_init_sha256": self.init_digest,
            "archive_sha256": self.cpio_digest,
        }))

    def emit_mock(self, run_id=33):
        with mock.patch.object(audit, "local_git_commit", return_value=audit.BASE), \
             mock.patch.object(audit, "version", return_value="19.1.4"):
            return audit.emit(
                image=self.image, config=self.config, patch=self.patch,
                init_evidence=self.init, cpio_evidence=self.cpio,
                source=self.root, run_id=str(run_id), attempt="1",
                galwear_commit=BASE_SHA, container_image_id=IMAGE_ID)

    def test_one_successful_build_is_not_reproducibility_proof(self):
        result = self.emit_mock()
        self.assertEqual(result["status"], "ONE_BUILD_EVIDENCE_ONLY")
        self.assertTrue(result["kernel_compiled"])
        self.assertTrue(result["cpio_verified"])
        self.assertFalse(result["reproducibility_proven"])
        self.assertFalse(result["safe_to_flash"])
        self.assertEqual(len(result["image_sha256"]), 64)

    def test_two_independent_identical_runs_report_limited_match(self):
        first = self.emit_mock(33)
        second = self.emit_mock(34)
        result = audit.compare(first, second)
        self.assertEqual(result["status"], "TWO_RUN_HASH_MATCH")
        self.assertTrue(result["two_run_byte_identity_observed"])
        self.assertFalse(result["general_reproducibility_proven"])
        self.assertFalse(result["container_packages_fully_pinned"])

    def test_same_run_attempt_cannot_prove_repetition(self):
        manifest = self.emit_mock(33)
        with self.assertRaisesRegex(audit.EvidenceError, "independent"):
            audit.compare(manifest, copy.deepcopy(manifest))

    def test_other_attempt_same_run_is_independent_attempt(self):
        first = self.emit_mock(33)
        second = copy.deepcopy(first)
        second["run_attempt"] = 2
        result = audit.compare(first, second)
        self.assertTrue(result["two_run_byte_identity_observed"])

    def test_matrix_replicas_same_run_are_independent(self):
        first = self.emit_mock(33)
        second = self.emit_mock(33)
        first["runner_replica"] = "a"
        second["runner_replica"] = "b"
        comparison = audit.compare(first, second)
        self.assertEqual(comparison["status"], "TWO_RUN_HASH_MATCH")
        self.assertEqual(comparison["first_runner_replica"], "a")
        self.assertEqual(comparison["second_runner_replica"], "b")

    def test_same_replica_same_run_rejected(self):
        first = self.emit_mock(33)
        second = self.emit_mock(33)
        first["runner_replica"] = second["runner_replica"] = "a"
        with self.assertRaisesRegex(audit.EvidenceError, "independent"):
            audit.compare(first, second)

    def test_invalid_replica_manifest_rejected(self):
        first = self.emit_mock(33)
        first["runner_replica"] = "third"
        with self.assertRaisesRegex(audit.EvidenceError, "runner replica"):
            audit.validate_manifest(first)

    def test_mismatched_kernel_with_matrix_replicas_reports_failure(self):
        first = self.emit_mock(33)
        self.image.write_bytes(b"MISMATCHED-IMAGE" * 100)
        second = self.emit_mock(33)
        first["runner_replica"] = "a"
        second["runner_replica"] = "b"
        result = audit.compare(first, second)
        self.assertEqual(result["status"], "REJECT_MISMATCH")
        self.assertIn("image_sha256", result["differences"])

    def test_different_kernel_image_rejected(self):
        first = self.emit_mock(33)
        self.image.write_bytes(b"DIFFERENT NON-RELEASE IMAGE")
        second = self.emit_mock(34)
        result = audit.compare(first, second)
        self.assertEqual(result["status"], "REJECT_MISMATCH")
        self.assertIn("image_sha256", result["differences"])
        self.assertFalse(result["safe_to_flash"])

    def test_different_kernel_config_rejected(self):
        first = self.emit_mock(33)
        self.config.write_text(self.config.read_text() + "CONFIG_FAKE=y\n")
        second = self.emit_mock(34)
        result = audit.compare(first, second)
        self.assertIn("kernel_config_sha256", result["differences"])

    def test_different_container_identity_detected(self):
        first = self.emit_mock(33)
        second = self.emit_mock(34)
        second["container_image_id"] = "sha256:" + "ef" * 32
        result = audit.compare(first, second)
        self.assertIn("container_image_id", result["differences"])

    def test_invalid_firmware_readiness_flags_rejected(self):
        first = self.emit_mock(33)
        second = self.emit_mock(34)
        second["safe_to_flash"] = True
        with self.assertRaisesRegex(audit.EvidenceError, "safety"):
            audit.compare(first, second)

    def test_unverified_cpio_rejected_at_emit(self):
        data = json.loads(self.cpio.read_text())
        data["embedded_init_exact_match"] = False
        self.cpio.write_text(json.dumps(data))
        with self.assertRaisesRegex(audit.EvidenceError, "CPIO byte comparison"):
            self.emit_mock()

    def test_mismatched_init_digests_rejected_at_emit(self):
        data = json.loads(self.cpio.read_text())
        data["embedded_init_sha256"] = "34" * 32
        self.cpio.write_text(json.dumps(data))
        with self.assertRaisesRegex(audit.EvidenceError, "different init"):
            self.emit_mock()

    def test_symlinked_image_rejected(self):
        link = self.root / "linked-image"
        try:
            link.symlink_to(self.image)
        except (OSError, NotImplementedError):
            self.skipTest("Symlinks unsupported")
        with self.assertRaisesRegex(audit.EvidenceError, "symlinked"):
            audit.hash_file(link, audit.MAX_IMAGE)

    def test_invalid_container_image_id_rejected(self):
        with mock.patch.object(audit, "local_git_commit", return_value=audit.BASE):
            with self.assertRaisesRegex(audit.EvidenceError, "Container"):
                audit.emit(image=self.image, config=self.config, patch=self.patch,
                           init_evidence=self.init, cpio_evidence=self.cpio,
                           source=self.root, run_id="33", attempt="1",
                           galwear_commit=BASE_SHA, container_image_id="alpine:latest")

    def test_strict_missing_json_rejected(self):
        self.init.unlink()
        with self.assertRaisesRegex(audit.EvidenceError, "Evidence JSON"):
            self.emit_mock()

    def test_invalid_old_source_sha_rejected(self):
        a = self.emit_mock(33)
        b = self.emit_mock(34)
        b["source_commit"] = "0" * 40
        with self.assertRaisesRegex(audit.EvidenceError, "source revision"):
            audit.compare(a, b)

    def test_cli_compares_without_accessing_network(self):
        a = self.emit_mock(33)
        b = self.emit_mock(34)
        first, second, out = (self.root / n for n in ("a.json", "b.json", "compare.json"))
        first.write_text(json.dumps(a))
        second.write_text(json.dumps(b))
        with mock.patch("socket.socket", side_effect=AssertionError("No sockets allowed")):
            with redirect_stdout(io.StringIO()):
                result = audit.main(["--output", str(out), "compare",
                                     "--first", str(first), "--second", str(second)])
        self.assertEqual(result, 0)
        self.assertEqual(json.loads(out.read_text())["status"], "TWO_RUN_HASH_MATCH")

    def test_cli_mismatch_returns_nonzero_json(self):
        a = self.emit_mock(33)
        b = self.emit_mock(34)
        b["embedded_cpio_sha256"] = "42" * 32
        first, second, out = (self.root / n for n in ("a.json", "b.json", "compare.json"))
        first.write_text(json.dumps(a))
        second.write_text(json.dumps(b))
        with redirect_stdout(io.StringIO()):
            result = audit.main(["--output", str(out), "compare",
                                 "--first", str(first), "--second", str(second)])
        self.assertEqual(result, 2)
        self.assertIn("embedded_cpio_sha256", json.loads(out.read_text())["differences"])

    def test_invalid_non_release_status_rejected(self):
        a = self.emit_mock(33)
        a["status"] = "SUCCESS_FLASHABLE"
        with self.assertRaisesRegex(audit.EvidenceError, "Invalid"):
            audit.validate_manifest(a)


if __name__ == "__main__":
    unittest.main()
