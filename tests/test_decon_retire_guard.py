"""Synthetic DECON retire guard utility tests."""
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"build"))
import r800_decon_retire_guard as mod

class DeconRetireGuardTests(unittest.TestCase):
    def test_extract(self):
        self.assertEqual(mod.extract("int foo(void)\n{\n return 0;\n}\n","int foo("),
                         "int foo(void)\n{\n return 0;\n}\n")

    def test_missing_signature(self):
        with self.assertRaises(ValueError):
            mod.extract("bad","static int decon_get_valid_fd(")
