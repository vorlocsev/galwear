"""Offline acquire wait policy checks."""
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"build"))
import r800_decon_acquire_guard as mod

class DeconAcquireGuardTests(unittest.TestCase):
    def test_error_precedence_cases(self):
        self.assertIn((1,-4,0,-4),mod.CASES)
        self.assertIn((1,0,1,-110),mod.CASES)
        self.assertIn((1,5,-5,-5),mod.CASES)

    def test_video_policy_unchanged(self):
        self.assertIn((0,5,-5,1),mod.CASES)
        self.assertIn((0,0,0,-110),mod.CASES)
