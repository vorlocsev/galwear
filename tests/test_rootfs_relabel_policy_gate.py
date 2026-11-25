"""Compiled-policy query contract (mocked sesearch, no actual policy load)."""
import subprocess
import sys
from pathlib import Path
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/"build"))
import r800_rootfs_relabel_policy_gate as a
from r800_qemu_system_init import classify_console

class RelabelPolicyTests(unittest.TestCase):
    def test_unconditional_attribute_allow(self):
        with patch.object(a.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, stdout="allow kernel file_type:dir { getattr relabelto };\n")) as run:
            r = a.allow_query(Path("policy"), "system_file", "dir", "relabelto")
        self.assertTrue(r["unconditional_allow_found"])
        self.assertEqual(run.call_args.args[0], ["sesearch", "--allow", "-s", "kernel", "-t", "system_file", "-c", "dir", "-p", "relabelto", "policy"])

    def test_conditional_not_evidence(self):
        with patch.object(a.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, stdout="allow kernel system_file:dir relabelto; [ feature ]:True\n")):
            self.assertFalse(a.allow_query(Path("policy"), "system_file", "dir", "relabelto")["unconditional_allow_found"])

    def test_missing_permissions_block(self):
        with patch.object(a.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, stdout="")):
            r = a.evaluate(Path("policy"))
        self.assertEqual(r["status"], "ROOTFS_RELABEL_POLICY_BLOCKED")
        self.assertEqual(len(r["missing_unconditional_permissions"]), len(a.CHECKS))
        self.assertFalse(r["safe_to_flash"])

    def test_allows_do_not_prove_relabel(self):
        with patch.object(a.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, stdout="allow kernel file_type:dir relabelto;\n")):
            r = a.evaluate(Path("policy"))
        self.assertEqual(r["status"], "ROOTFS_RELABEL_POLICY_PREREQUISITES_ONLY")
        self.assertFalse(r["full_relabel_feasibility_proven"])

    def test_tool_failure_propagates(self):
        with patch.object(a.subprocess, "run", side_effect=subprocess.CalledProcessError(2, "sesearch")):
            with self.assertRaises(subprocess.CalledProcessError):
                a.evaluate(Path("policy"))

    def test_initramfs_unpack_failure_is_fatal(self):
        for line in (b"Initramfs unpacking failed: invalid magic at start of compressed archive",
                     b"initramfs unpacking failed: junk in compressed archive"):
            with self.assertRaisesRegex(ValueError, "critical diagnostic"):
                classify_console([line])

if __name__ == "__main__":
    unittest.main()
