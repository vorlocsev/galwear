"""Rootfs boot gate: synthetic console and exact archive verification."""
from pathlib import Path
from types import SimpleNamespace
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "build"))
import r800_qemu_rootfs_preflight as a

LOG = a.EXPECTED + b"\n".join(a.MARKERS) + b"\n" + a.HEARTBEAT_PREFIX + b"00000001\n"

class RootfsBootTests(unittest.TestCase):
    def test_complete(self):
        report = a.inspect_console(LOG)
        self.assertTrue(report["ram_mounts_reported"])
        self.assertFalse(report["android_init_started"])
        self.assertFalse(report["property_service_started"])
        self.assertFalse(report["selinux_policy_loaded"])

    def test_missing_or_duplicate_markers(self):
        for marker in a.MARKERS:
            for log in (LOG.replace(marker, b""), LOG.replace(marker, marker+b"\n"+marker)):
                with self.assertRaisesRegex(ValueError, "diagnostic sequence"):
                    a.inspect_console(log)

    def test_early_heartbeat(self):
        with self.assertRaisesRegex(ValueError, "Heartbeat before"):
            a.inspect_console(LOG.replace(a.MARKERS[-1]+b"\n", b"")+a.MARKERS[-1]+b"\n")

    def test_unexpected_android_service(self):
        with self.assertRaisesRegex(ValueError, "Unexpected Android"):
            a.inspect_console(LOG + b"r800-property-service: original-libinit socket-created\n")

    def test_archive_exact_match(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "preflight.cpio"
            p.write_bytes(b"canonical")
            a.verify_archive(p, b"canonical")
            p.write_bytes(b"canonical\0")
            with self.assertRaisesRegex(ValueError, "canonical"):
                a.verify_archive(p, b"canonical")

    def test_no_external_devices(self):
        cmd = a.command(Path("/tmp/Image"), Path("/tmp/initrd"))
        for forbidden in ("-drive", "-blockdev", "-device", "-netdev", "-virtfs"):
            self.assertNotIn(forbidden, cmd)
        self.assertIn("-nodefaults", cmd)
        self.assertEqual(cmd[cmd.index("-nic")+1], "none")
        self.assertEqual(cmd[cmd.index("-m")+1], "512M")

    def test_wrong_kernel_rejected_before_archive(self):
        args = SimpleNamespace(baseline=None, kernel=None, config_evidence=None, prepolicy=None)
        with patch.object(a, "verify_baseline", return_value="wrong"), \
             patch.object(a, "verify_config", return_value={}), \
             patch.object(a, "verify_prepolicy"), \
             patch.object(a, "kernel_bytes", return_value=b"kernel"), \
             patch.object(a, "prepare") as prepare:
            with self.assertRaisesRegex(ValueError, "Kernel changed"):
                a.run(args)
            prepare.assert_not_called()

if __name__ == "__main__":
    unittest.main()
