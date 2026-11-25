import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "build"))
import r800_qemu_property_area as a

LOG = a.EXPECTED + b"\n".join(a.MARKERS) + b"\n" + a.HEARTBEAT_PREFIX + b"00000001\n"

class PropertyAreaTests(unittest.TestCase):
    def test_complete(self):
        result = a.inspect_console(LOG)
        self.assertTrue(result["property_update_wait_reported"])
        self.assertFalse(result["property_service_started"])
        self.assertFalse(result["android_init_started"])

    def test_missing_or_duplicate(self):
        for marker in a.MARKERS:
            for log in (LOG.replace(marker, b""), LOG.replace(marker, marker+b"\n"+marker)):
                with self.assertRaisesRegex(ValueError, "sequence"):
                    a.inspect_console(log)

    def test_early_heartbeat(self):
        with self.assertRaisesRegex(ValueError, "Heartbeat before"):
            a.inspect_console(LOG.replace(a.MARKERS[-1]+b"\n", b"")+a.MARKERS[-1]+b"\n")

    def test_policy_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "report.json"
            result = {"status": "VIRT_SELINUX_FIXTURE_ONLY", "generic_kernel_sha256": "kernel",
                      "same_dac_allow_deny_reported": True, "enforcing_reported": True,
                      "safe_to_flash": False, "policy_compile_evidence": {"policy_sha256": "policy"}}
            p.write_text(json.dumps(result))
            a.verify_policy_run(p, "kernel", "policy")
            for kernel, policy in (("wrong", "policy"), ("kernel", "wrong")):
                with self.assertRaisesRegex(ValueError, "same-policy"):
                    a.verify_policy_run(p, kernel, policy)

    def test_embedded_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "init"
            p.write_bytes(b"prefixPOLICYmiddleINFObody")
            self.assertEqual(a.verify_embedded(p, b"POLICY", b"INFO"), a.sha(p.read_bytes()))
            for data in (b"POLICY", b"POLICYPOLICYINFO"):
                p.write_bytes(data)
                with self.assertRaisesRegex(ValueError, "missing or ambiguous"):
                    a.verify_embedded(p, b"POLICY", b"INFO")

if __name__ == "__main__":
    unittest.main()
