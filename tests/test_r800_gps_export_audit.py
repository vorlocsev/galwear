"""Unit tests for GPS export classification, using synthetic ELF inventories."""
import hashlib
from pathlib import Path
import struct
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "build"))
import r800_gps_export_audit as target


def symbol(name=target.FACTORY, **changes):
    return dict({"name": name, "type": 2, "binding": 1, "visibility": 0,
                 "version_hidden": False}, **changes)


class ExportTests(unittest.TestCase):
    def run_audit(self, exports=None, flags=0x05000000, marker=True, **changes):
        raw = bytearray(80)
        struct.pack_into("<I", raw, 36, flags)
        if marker:
            raw[64:73] = target.MARKER
        info = dict({"abi": "arm", "elf_type": "ET_DYN", "has_dynamic": True,
                     "dynamic_symbol_count": 3, "unsupported_symbols": [],
                     "soname": "libbrcm.so", "needed": ["libc.so.6"],
                     "symbol_exports": [symbol()] if exports is None else exports},
                    **changes)
        with patch.object(target, "inspect", return_value=info):
            report = target.audit(bytes(raw))
        self.assertEqual(report["sha256"], hashlib.sha256(raw).hexdigest())
        self.assertIsNone(report["selected_abi"])
        for field in ("factory_signature_verified", "extension_available_verified",
                      "callback_layout_verified", "runtime_verified", "safe_to_flash"):
            self.assertFalse(report[field])
        return report

    def test_factory_and_marker_only(self):
        report = self.run_audit()
        self.assertEqual(report["status"], "STATIC_EXPORT_EVIDENCE_ONLY")
        self.assertEqual(report["xtra_literal_count"], 1)
        self.assertEqual(report["xtra_literal_first_offset"], 64)

    def test_marker_absence_is_not_negative_runtime_evidence(self):
        report = self.run_audit(marker=False)
        self.assertEqual(report["status"], "STATIC_EXPORT_EVIDENCE_ONLY")
        self.assertIsNone(report["xtra_literal_first_offset"])

    def test_missing_or_ambiguous_factory(self):
        for exports in ([], [symbol(), symbol()]):
            with self.subTest(exports=exports):
                self.assertEqual(self.run_audit(exports)["status"], "REVIEW_REQUIRED")

    def test_noncallable_factory(self):
        for changes in ({"type": 1}, {"version_hidden": True}, {"binding": 0},
                        {"visibility": 2}, {"type": 10}):
            with self.subTest(changes=changes):
                self.assertEqual(self.run_audit([symbol(**changes)])["status"],
                                 "REVIEW_REQUIRED")

    def test_wrong_elf_contract(self):
        for changes in ({"abi": "arm64"}, {"elf_type": "ET_EXEC"},
                        {"has_dynamic": False}, {"flags": 0x05000400},
                        {"flags": 0x04000000}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.run_audit(**changes)

    def test_incomplete_or_wrong_soname(self):
        for changes in ({"dynamic_symbol_count": None}, {"unsupported_symbols": [{}]},
                        {"soname": "unrelated.so"}):
            with self.subTest(changes=changes):
                self.assertEqual(self.run_audit(**changes)["status"], "REVIEW_REQUIRED")

    def test_export_clues_are_bounded_and_do_not_select_abi(self):
        exports = [symbol()] + [symbol("xtra_" + str(i)) for i in range(300)]
        report = self.run_audit(exports)
        self.assertEqual(report["xtra_export_clue_count"], 300)
        self.assertEqual(len(report["xtra_export_clues"]), 256)
        self.assertFalse(report["callback_layout_verified"])


if __name__ == "__main__":
    unittest.main()
