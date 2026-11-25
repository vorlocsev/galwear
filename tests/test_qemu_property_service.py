"""Synthetic integrated service acceptance; no actual AOSP boot implied."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/"build"))
import r800_qemu_property_service as a
from r800_qemu_user_init import EXPECTED

PATHS = ["/system/bin/init", a.FILE, a.SERVICE, "/dev/socket"]
LABELS = ["u:object_r:init_exec:s0", a.LABEL, a.SERVICE_LABEL, "u:object_r:socket_device:s0"]
LOG = (EXPECTED + a.PREFIX+b"fixture-policy=PASS enforce=1\n" +
       b"".join(a.PREFIX+b"path="+p.encode()+b" context="+l.encode()+b"\n"
                for p,l in zip(PATHS,LABELS)) +
       a.PREFIX+b"PASS count=4 service=handover\n" +
       b"\n".join(a.MARKERS)+b"\n"+a.HEARTBEAT_PREFIX+b"00000001\n")

class ServiceTests(unittest.TestCase):
    def test_complete_is_fixture_only(self):
        r = a.inspect_console(LOG, PATHS)
        self.assertTrue(r["property_service_started"])
        self.assertFalse(r["android_init_started"])
        self.assertFalse(r["stock_policy"])
        self.assertFalse(r["safe_to_flash"])

    def test_missing_or_duplicate_marker(self):
        for m in a.MARKERS:
            for v in (LOG.replace(m, b""), LOG.replace(m, m+b"\n"+m)):
                with self.assertRaisesRegex(ValueError, "sequence"):
                    a.inspect_console(v, PATHS)

    def test_wrong_protocol_error(self):
        with self.assertRaisesRegex(ValueError, "sequence"):
            a.inspect_console(LOG.replace(b"status=0x0018", b"status=0x000b"), PATHS)

    def test_stock_policy_cannot_substitute(self):
        with self.assertRaisesRegex(ValueError, "fixture-policy"):
            a.inspect_console(LOG.replace(b"fixture-policy=", b"stock-policy="), PATHS)

    def test_wrong_client_exec_label(self):
        with self.assertRaisesRegex(ValueError, "executable labels"):
            a.inspect_console(LOG.replace(a.LABEL.encode(), b"u:object_r:system_file:s0"), PATHS)

    def test_early_heartbeat(self):
        v = LOG.replace(a.MARKERS[-1], a.HEARTBEAT_PREFIX+b"00000001\n"+a.MARKERS[-1])
        with self.assertRaisesRegex(ValueError, "Heartbeat before"):
            a.inspect_console(v, PATHS)

    def test_wrong_kernel_control(self):
        with self.assertRaisesRegex(ValueError, "stock rootfs"):
            a.verify_prior({"status": "VIRT_ANDROID_ROOTFS_RELABEL_ONLY",
                            "generic_kernel_sha256": "wrong"}, "expected")

if __name__ == "__main__":
    unittest.main()
