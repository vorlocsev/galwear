"""Synthetic evidence tests for the distinct property profile."""
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "build"))
import r800_qemu_property_kernel as a

LOG = a.EXPECTED + b"\n".join(a.MARKERS) + b"\n" + a.HEARTBEAT_PREFIX + b"00000001\n"


class PropertyTests(unittest.TestCase):
    def test_complete_prepolicy(self):
        report = a.inspect_console(LOG)
        self.assertTrue(report["unix_peer_credentials_reported"])
        self.assertTrue(report["security_label_io_reported"])
        for key in ("effective_selinux_label_verified", "selinux_policy_loaded",
                    "selinux_access_control_tested", "property_service_started"):
            self.assertFalse(report[key])

    def test_missing_or_duplicate(self):
        for marker in a.MARKERS:
            for log in (LOG.replace(marker, b""), LOG.replace(marker, marker + b"\n" + marker)):
                with self.assertRaisesRegex(ValueError, "diagnostic sequence"):
                    a.inspect_console(log)

    def test_wrong_enforce_value(self):
        with self.assertRaisesRegex(ValueError, "diagnostic sequence"):
            a.inspect_console(LOG.replace(b"enforce=1", b"enforce=0"))

    def test_early_heartbeat(self):
        with self.assertRaisesRegex(ValueError, "Heartbeat before"):
            a.inspect_console(LOG.replace(a.MARKERS[-1] + b"\n", b"") + a.MARKERS[-1] + b"\n")

    def test_wrong_profile_or_image(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "config.json"
            cfg = {"status": "VIRT_CONFIG_STATIC_ONLY", "profile": "property",
                   "compiled_kernel_sha256": "digest", "safe_to_flash": False}
            p.write_text(json.dumps(cfg))
            self.assertEqual(a.verify_config(p, "digest"), cfg)
            for key, value in (("profile", "minimal"), ("compiled_kernel_sha256", "wrong"),
                               ("safe_to_flash", True)):
                p.write_text(json.dumps({**cfg, key: value}))
                with self.assertRaisesRegex(ValueError, "compiled property profile"):
                    a.verify_config(p, "digest")


if __name__ == "__main__":
    unittest.main()
