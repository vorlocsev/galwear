"""Offline tests for rejected-frame branch extraction."""
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"build"))
import r800_decon_buffer_guard as mod

class DeconBufferGuardTests(unittest.TestCase):
    def test_extract_failure_branch(self):
        source=("static void decon_update_regs(void)\n{\n"
                " err = decon_wait_fence();\n if (err <= 0) {\n"
                " goto fence_err;\n }\n}\n")
        self.assertEqual(mod.failure_branch(source),"if (err <= 0) {\n goto fence_err;\n}")

    def test_missing_wait_rejected(self):
        with self.assertRaises(ValueError):
            mod.failure_branch("static void decon_update_regs(void)\n{\n}\n")
