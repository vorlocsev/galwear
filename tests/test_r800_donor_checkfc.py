import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from subprocess import CompletedProcess

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "build"))
import r800_donor_cil_compile as c


class CheckfcContractTests(unittest.TestCase):
    def test_modes_and_rejection(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            tool, policy, context = (root / n for n in ("checkfc", "policy", "contexts"))
            tool.write_bytes(b"mock tool")
            policy.write_bytes(b"mock policy")
            context.write_bytes(b"fixture u:object_r:fixture_t:s0\n")
            digest = c.sha(tool.read_bytes())
            inputs = [(kind, context, c.sha(context.read_bytes())) for kind in c.CHECKFC_MODES]
            with patch.object(c.subprocess, "run", side_effect=[
                    CompletedProcess([], 0, b"", b""),
                    CompletedProcess([], 0, b"", b""),
                    CompletedProcess([], 0, b"", b""),
                    CompletedProcess([], 1, b"", b"invalid hwservice"),
                    CompletedProcess([], 0, b"", b"")]) as run:
                report = c.audit_checkfc(policy, tool, digest, inputs)
            self.assertEqual(report["status"], "REVIEW_REQUIRED")
            self.assertEqual(report["checks"][3]["status"], "REVIEW_REQUIRED")
            self.assertEqual([call.args[0][1:-2] for call in run.call_args_list],
                             [[], ["-p"], ["-s"], ["-l"], ["-v"]])
            self.assertFalse(report["policy_loaded"])
            self.assertFalse(report["safe_to_flash"])
            with self.assertRaisesRegex(ValueError, "checkfc SHA-256"):
                c.audit_checkfc(policy, tool, "0"*64, inputs)
            with self.assertRaisesRegex(ValueError, "context SHA-256"):
                c.audit_checkfc(policy, tool, digest, [("file", context, "0"*64)])


if __name__ == "__main__":
    unittest.main()
