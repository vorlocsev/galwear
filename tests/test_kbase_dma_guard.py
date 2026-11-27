"""Synthetic-only KBASE DMA guard source extraction tests."""
from pathlib import Path
import sys
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]/"build"))
import r800_kbase_dma_guard as mod

class KbaseDmaGuardTests(unittest.TestCase):
    def test_guard_delta(self):
        self.assertIn("IS_ERR_OR_NULL(dma_attachment)", mod.NEW)
        self.assertIn("goto no_attachment;", mod.NEW)
        self.assertNotIn("IS_ERR_OR_NULL", mod.OLD)

    def test_unexpected_source_rejected(self):
        with self.assertRaises(ValueError):
            mod.fragments("invalid")
