"""Synthetic restorecon and transition acceptance tests."""
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "build"))
import r800_qemu_selinux_transition as a
import r800_android_file_contexts as f

LOG = a.EXPECTED + b"\n".join(a.MARKERS) + b"\n" + a.HEARTBEAT_PREFIX + b"00000001\n"

class TransitionTests(unittest.TestCase):
    def test_success_is_diagnostic_only(self):
        result = a.inspect_console(LOG)
        self.assertTrue(result["init_domain_entered"])
        self.assertFalse(result["android_init_started"])
        self.assertFalse(result["property_service_started"])

    def test_wrong_domain(self):
        with self.assertRaisesRegex(ValueError, "sequence"):
            a.inspect_console(LOG.replace(b"domain=u:r:init:s0", b"domain=u:r:kernel:s0"))

    def test_wrong_label(self):
        with self.assertRaisesRegex(ValueError, "sequence"):
            a.inspect_console(LOG.replace(b"init_exec:s0", b"system_file:s0"))

    def test_permissive(self):
        with self.assertRaisesRegex(ValueError, "sequence"):
            a.inspect_console(LOG.replace(b"enforce=1", b"enforce=0"))

    def test_early_heartbeat(self):
        with self.assertRaisesRegex(ValueError, "Heartbeat before"):
            a.inspect_console(LOG.replace(a.MARKERS[-1]+b"\n", b"")+a.MARKERS[-1]+b"\n")

    def test_archive_has_diagnostic_twice(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)/"init"
            p.write_bytes(b"diagnostic-binary")
            info = {"sha256": a.sha(p.read_bytes())}
            with patch.object(a, "validate_init", return_value=info), \
                 patch.object(a, "read_bounded_json", return_value={
                     "status": "NON_RELEASE_INITRAMFS_SPEC_ONLY", "init": info}):
                blob, digest = a.make_archive(p, None, b"policy", {f.FILE_CONTEXTS[0]: b"contexts"})
            self.assertEqual(blob.count(b"diagnostic-binary"), 2)
            self.assertIn(b"system/bin/init\0", blob)
            self.assertIn(f.FILE_CONTEXTS[0].encode()+b"\0", blob)
            self.assertEqual(digest, info["sha256"])

    def test_wrong_policy_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(f, "audit", return_value={"policy_sha256": "new"}):
                with self.assertRaisesRegex(ValueError, "matching stock policy"):
                    f.audit_files(Path(tmp), Path("checkfc"), {"policy_sha256": "old"})

    def test_missing_restorecon_marker(self):
        with self.assertRaisesRegex(ValueError, "sequence"):
            a.inspect_console(LOG.replace(a.MARKERS[1]+b"\n", b""))

if __name__ == "__main__":
    unittest.main()
