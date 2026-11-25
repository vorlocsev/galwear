"""Synthetic stock policy boot gate checks."""
import hashlib
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "build"))
import r800_qemu_android_stock_policy as a

LOG = a.EXPECTED + b"\n".join(a.MARKERS) + b"\n" + a.HEARTBEAT_PREFIX + b"00000001\n"

class StockPolicyTests(unittest.TestCase):
    def test_complete(self):
        result = a.inspect_console(LOG)
        self.assertTrue(result["stock_policy_loaded_reported"])
        self.assertTrue(result["enforcing_reported"])
        self.assertFalse(result["init_domain_entered"])
        self.assertFalse(result["file_relabel_tested"])
        self.assertFalse(result["android_init_started"])

    def test_wrong_domain(self):
        with self.assertRaisesRegex(ValueError, "diagnostic sequence"):
            a.inspect_console(LOG.replace(b"u:r:kernel:s0", b"u:r:init:s0"))

    def test_missing_duplicate_or_permissive(self):
        for marker in a.MARKERS:
            for log in (LOG.replace(marker, b""), LOG.replace(marker, marker+b"\n"+marker)):
                with self.assertRaisesRegex(ValueError, "sequence"):
                    a.inspect_console(log)
        with self.assertRaisesRegex(ValueError, "sequence"):
            a.inspect_console(LOG.replace(b"enforce=1", b"enforce=0"))

    def test_early_heartbeat(self):
        with self.assertRaisesRegex(ValueError, "Heartbeat before"):
            a.inspect_console(LOG.replace(a.MARKERS[-1]+b"\n", b"")+a.MARKERS[-1]+b"\n")

    def test_unexpected_service(self):
        with self.assertRaisesRegex(ValueError, "Unexpected other"):
            a.inspect_console(LOG+b"r800-property-service: socket-created\n")

    def test_rootfs_identity(self):
        with tempfile.TemporaryDirectory() as temp:
            p = Path(temp)/"rootfs.cpio"
            p.write_bytes(b"archive")
            digest = hashlib.sha256(p.read_bytes()).hexdigest()
            contexts = {"system/etc/selinux/plat_property_contexts": "b"*64}
            report = {"status": "VIRT_ANDROID_ROOTFS_PREFLIGHT_ONLY",
                      "generic_kernel_sha256": "kernel", "canonical_archive_verified": True,
                      "ram_mounts_reported": True, "guest_progress_after_marker_verified": True,
                      "selinux_policy_loaded": False, "safe_to_flash": False,
                      "property_contexts_sha256": contexts, "archive_sha256": digest}
            policy = {"property_contexts_sha256": contexts}
            self.assertEqual(a.verify_previous(report, policy, "kernel", p), digest)
            with self.assertRaisesRegex(ValueError, "same-kernel"):
                a.verify_previous(report, policy, "wrong", p)
            p.write_bytes(b"changed")
            with self.assertRaisesRegex(ValueError, "archive identity"):
                a.verify_previous(report, policy, "kernel", p)

    def test_archive_separate_from_rootfs(self):
        with tempfile.TemporaryDirectory() as temp:
            p = Path(temp)/"init"
            p.write_bytes(b"static fixture")
            info = {"sha256": a.sha(p.read_bytes())}
            with patch.object(a, "validate_init", return_value=info), \
                 patch.object(a, "read_bounded_json", return_value={
                     "status": "NON_RELEASE_INITRAMFS_SPEC_ONLY", "init": info}):
                archive, digest = a.archive_for(p, None, b"stock policy fixture")
                self.assertEqual(digest, info["sha256"])
                self.assertIn(b"galwear-policy\0", archive)
                self.assertIn(b"stock policy fixture", archive)
                self.assertNotIn(b"system/bin/init", archive)

if __name__ == "__main__":
    unittest.main()
