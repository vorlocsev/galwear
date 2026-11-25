"""Synthetic policy header, partition IDs and checkfc invocation contracts."""
import struct
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "build"))
import r800_android_sepolicy_audit as a

def policy(version=30, config=1):
    return struct.pack("<II", 0xf97cff8c, 8) + b"SE Linux" + struct.pack("<IIII", version, config, 8, 9)

class PolicyAuditTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.tool = self.root / "checkfc"
        self.tool.write_bytes(b"fixture")
        self.rel = a.POLICY_PATHS[1]
        self.write(self.rel, policy())
        for part, stem in a.PARTITIONS:
            suffix = stem + "_sepolicy_and_mapping.sha256"
            self.write(part + "/etc/selinux/" + suffix, b"a"*64+b"\n")
            self.write(self.rel + "." + suffix, b"a"*64+b"\n")
        self.write(a.CONTEXTS[0], b"debug. u:object_r:debug_prop:s0 prefix string\n")

    def write(self, rel, data):
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)

    def test_header_bounds(self):
        for version in (19, 30, 31):
            self.assertEqual(a.header(policy(version))["policy_version"], version)
        for version in (18, 32):
            with self.assertRaisesRegex(ValueError, "version"):
                a.header(policy(version))

    def test_invalid_header(self):
        for data in (b"fake", b"\0"*32, policy(config=0)):
            with self.assertRaises(ValueError):
                a.header(data)

    def test_static_audit(self):
        with patch.object(a.subprocess, "run") as run:
            report = a.audit(self.root, self.tool)
        self.assertTrue(report["partition_ids_matched"])
        self.assertTrue(report["checkfc_property_contexts_passed"])
        self.assertFalse(report["policy_loaded"])
        self.assertFalse(report["kernel_policy_compatibility_tested"])
        self.assertEqual(run.call_args.args[0][1], "-p")
        self.assertTrue(run.call_args.kwargs["check"])

    def test_partition_id_mismatch(self):
        self.write(self.rel+".product_sepolicy_and_mapping.sha256", b"b"*64)
        with patch.object(a.subprocess, "run") as run:
            with self.assertRaisesRegex(ValueError, "ID mismatch"):
                a.audit(self.root, self.tool)
            run.assert_not_called()

    def test_odm_precedence_no_fallback(self):
        self.write(a.POLICY_PATHS[0], policy())
        with self.assertRaises(ValueError):
            a.audit(self.root, self.tool)

    def test_missing_platform_contexts(self):
        (self.root / a.CONTEXTS[0]).unlink()
        with self.assertRaisesRegex(ValueError, "contexts missing"):
            a.audit(self.root, self.tool)

    def test_rootfs_identity(self):
        contexts = {a.CONTEXTS[0]: "b"*64}
        policy = {"property_contexts_sha256": contexts}
        rootfs = {"status": "VIRT_ANDROID_ROOTFS_PREFLIGHT_ONLY",
                  "safe_to_flash": False, "property_contexts_sha256": contexts,
                  "archive_sha256": "a"*64}
        self.assertEqual(a.verify_rootfs(policy, rootfs), "a"*64)
        with self.assertRaisesRegex(ValueError, "identity mismatch"):
            a.verify_rootfs(policy, {**rootfs, "property_contexts_sha256": {}})
        with self.assertRaisesRegex(ValueError, "archive identity"):
            a.verify_rootfs(policy, {**rootfs, "archive_sha256": "bad"})

    def test_checkfc_failure(self):
        with patch.object(a.subprocess, "run", side_effect=subprocess.CalledProcessError(1, "checkfc")):
            with self.assertRaises(subprocess.CalledProcessError):
                a.audit(self.root, self.tool)

if __name__ == "__main__":
    unittest.main()
