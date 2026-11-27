"""Offline completion extraction checks."""
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"build"))
import r800_decon_completion_guard as mod

class DeconCompletionGuardTests(unittest.TestCase):
    def test_completion_extract(self):
        source=("static void decon_update_regs(void)\n{\nfence_err:\n"
                " release();\n signal();\n DPU_EVENT_LOG(DPU_EVT_FENCE_RELEASE);\n}\n")
        self.assertEqual(mod.completion(source)," release();\n signal();\n ")

    def test_missing_label_rejected(self):
        with self.assertRaises(ValueError):
            mod.completion("static void decon_update_regs(void)\n{\n}\n")
