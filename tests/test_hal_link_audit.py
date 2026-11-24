"""Synthetic readelf output tests for the HAL link gate."""
from pathlib import Path
import sys
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "build"))
from r800_hal_link_audit import inspect

NAME = "gps.r800.so"
HEADER = "Class: ELF32\nType: DYN (Shared object file)\nMachine: ARM\n"
SYMBOLS = "  19: 00001000 128 OBJECT GLOBAL DEFAULT 21 HMI\n"
DYNAMIC = "  0x1 (NEEDED) Shared library: [libc.so]\n  0xe (SONAME) Library soname: [gps.r800.so]\n"


class HalLinkAuditTests(unittest.TestCase):
    def test_valid(self):
        self.assertTrue(inspect(HEADER, SYMBOLS, DYNAMIC, NAME)["hmi_exported"])

    def test_wrong_class(self):
        with self.assertRaises(ValueError):
            inspect(HEADER.replace("ELF32", "ELF64"), SYMBOLS, DYNAMIC, NAME)

    def test_wrong_type(self):
        with self.assertRaises(ValueError):
            inspect(HEADER.replace("DYN", "REL"), SYMBOLS, DYNAMIC, NAME)

    def test_missing_hmi(self):
        with self.assertRaises(ValueError):
            inspect(HEADER, SYMBOLS.replace("HMI", "other"), DYNAMIC, NAME)

    def test_undefined_hmi(self):
        with self.assertRaises(ValueError):
            inspect(HEADER, SYMBOLS.replace("21 HMI", "UND HMI"), DYNAMIC, NAME)

    def test_wrong_soname(self):
        with self.assertRaises(ValueError):
            inspect(HEADER, SYMBOLS, DYNAMIC.replace(NAME, "other.so"), NAME)

    def test_unexpected_dependency(self):
        with self.assertRaises(ValueError):
            inspect(HEADER, SYMBOLS, DYNAMIC.replace("libc.so", "libtinyalsa.so"), NAME)

    def test_runtime_search_path(self):
        with self.assertRaises(ValueError):
            inspect(HEADER, SYMBOLS, DYNAMIC + " (RUNPATH) [/tmp]\n", NAME)


if __name__ == "__main__":
    unittest.main()
