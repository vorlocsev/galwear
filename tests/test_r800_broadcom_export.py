"""Synthetic export metadata: no real donor ABI verification."""
from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "build"))
from r800_broadcom_export import EXPORT, assess


class ExportTests(unittest.TestCase):
    def setUp(self):
        self.raw = bytearray(52)
        struct.pack_into("<I", self.raw, 36, 0x05000200)
        self.symbol = {"name": EXPORT, "type": 2, "weak": False, "version_hidden": False}
        self.info = {"abi": "arm", "elf_type": "ET_DYN", "has_dynamic": True,
                     "dynamic_symbol_count": 2, "unsupported_symbols": [],
                     "custom_search_path": False, "symbol_exports": [self.symbol],
                     "needed": ["libc.so.6"]}

    def report(self):
        return assess(self.raw, self.info)

    def test_candidate(self):
        report = self.report()
        self.assertEqual(report["status"], "EXPORT_CANDIDATE")
        for key in ("hardware_interface_abi_verified", "xtra_abi_verified",
                    "runtime_verified", "safe_to_flash"):
            self.assertFalse(report[key])

    def test_wrong_types(self):
        for typ in (0, 1, 6, 10):
            with self.subTest(typ=typ):
                self.symbol["type"] = typ
                self.assertEqual(self.report()["status"], "REVIEW_REQUIRED")

    def test_hidden(self):
        self.symbol["version_hidden"] = True
        self.assertEqual(self.report()["status"], "REVIEW_REQUIRED")

    def test_weak(self):
        self.symbol["weak"] = True
        self.assertEqual(self.report()["status"], "REVIEW_REQUIRED")

    def test_missing(self):
        self.info["symbol_exports"] = []
        self.assertEqual(self.report()["status"], "REVIEW_REQUIRED")

    def test_ambiguous(self):
        self.info["symbol_exports"].append(dict(self.symbol))
        self.assertEqual(self.report()["status"], "REVIEW_REQUIRED")

    def test_hard_float(self):
        struct.pack_into("<I", self.raw, 36, 0x05000400)
        self.assertEqual(self.report()["status"], "REVIEW_REQUIRED")

    def test_incomplete_inventory(self):
        self.info["dynamic_symbol_count"] = None
        self.assertEqual(self.report()["status"], "REVIEW_REQUIRED")

    def test_wrong_elf_type(self):
        self.info["elf_type"] = "ET_EXEC"
        self.assertEqual(self.report()["status"], "REVIEW_REQUIRED")

    def test_search_path(self):
        self.info["custom_search_path"] = True
        self.assertEqual(self.report()["status"], "REVIEW_REQUIRED")


if __name__ == "__main__":
    unittest.main()
