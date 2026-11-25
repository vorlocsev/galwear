import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "build"))
import r800_virt_test_policy as p
import r800_qemu_selinux_policy as a

SOURCE = """type base_t;
role base_r types { base_t };
allow base_t base_t:file *;
user user_u roles { base_r };
fs_use_trans tmpfs user_u:base_r:base_t;
"""
LOG = a.EXPECTED + b"\n".join(a.MARKERS) + b"\n" + a.HEARTBEAT_PREFIX + b"00000001\n"

class PolicyTests(unittest.TestCase):
    def test_derive(self):
        result = p.derive(SOURCE)
        self.assertIn("type denied_t;", result)
        self.assertIn("allow base_t denied_t:file { getattr relabelto };", result)
        self.assertNotIn("allow base_t denied_t:file *;", result)
        self.assertNotIn("permissive", result)

    def test_missing_or_duplicate_template(self):
        for invalid in (SOURCE.replace("type base_t;", ""), SOURCE + SOURCE):
            with self.assertRaisesRegex(ValueError, "template"):
                p.derive(invalid)

    def test_exact_markers(self):
        result = a.inspect_console(LOG)
        self.assertTrue(result["same_dac_allow_deny_reported"])
        self.assertFalse(result["android_sepolicy_tested"])

    def test_missing_denial(self):
        with self.assertRaisesRegex(ValueError, "sequence"):
            a.inspect_console(LOG.replace(b"denied-read=EACCES", b"denied-read=PASS"))

    def test_early_heartbeat(self):
        with self.assertRaisesRegex(ValueError, "Heartbeat before"):
            a.inspect_console(LOG.replace(a.MARKERS[-1] + b"\n", b"") + a.MARKERS[-1] + b"\n")

if __name__ == "__main__":
    unittest.main()
