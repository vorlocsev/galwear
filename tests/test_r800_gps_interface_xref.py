"""Synthetic ELF32 reference tests; no donor execution."""
from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "build"))
import r800_gps_interface_xref as target
from test_r800_gps_interface_table import fixture


def image(isa="arm", relocation=23):
    raw = bytearray(fixture(relocs=[(0x2104, 23), (0x2108, 23), (0x1180, relocation)]))
    struct.pack_into("<I", raw, 0x180, 0x2100)
    if isa == "arm":
        struct.pack_into("<I", raw, 0x100, 0xe59f0078)
    else:
        struct.pack_into("<H", raw, 0x100, 0x481f)
    return bytes(raw)


class XrefTests(unittest.TestCase):
    def test_data_reference_without_code_claim(self):
        report = target.audit(image())
        self.assertEqual(report["relative_data_references"], [
            {"slot_va": 0x1180, "table_va": 0x2100, "source_executable": True}])
        self.assertEqual(report["code_ranges"], [])
        for flag in ("function_identity_verified", "instruction_boundaries_verified",
                     "table_identity_verified", "runtime_verified", "safe_to_flash"):
            self.assertFalse(report[flag])
        self.assertIsNone(report["selected_abi"])

    def test_arm_and_thumb_literal(self):
        for isa, size in (("arm", 4), ("thumb", 2)):
            with self.subTest(isa=isa):
                report = target.audit(image(isa), [("factory", isa, 0x1100, size)])
                self.assertEqual(report["code_ranges"][0]["literal_load_clues"], [
                    {"instruction_va": 0x1100, "register": "r0",
                     "literal_va": 0x1180, "table_va": 0x2100}])

    def test_nonrelative_word_ignored(self):
        report = target.audit(image(relocation=258), [("factory", "arm", 0x1100, 4)])
        self.assertEqual(report["relative_data_references"], [])
        self.assertEqual(report["code_ranges"][0]["literal_load_clues"], [])

    def test_thumb_wide_second_half_not_interpreted(self):
        raw = bytearray(image("thumb"))
        struct.pack_into("<HH", raw, 0x100, 0xf000, 0x481f)
        report = target.audit(bytes(raw), [("factory", "thumb", 0x1100, 4)])
        self.assertEqual(report["code_ranges"][0]["literal_load_clues"], [])
        with self.assertRaises(ValueError):
            target.audit(bytes(raw), [("factory", "thumb", 0x1100, 2)])

    def test_arm_negative_literal_offset(self):
        raw = bytearray(image())
        struct.pack_into("<I", raw, 0x190, 0xe51f1018)
        report = target.audit(bytes(raw), [("factory", "arm", 0x1190, 4)])
        self.assertEqual(report["code_ranges"][0]["literal_load_clues"][0]["register"], "r1")

    def test_bad_ranges(self):
        for item in (("factory", "arm", 0x1102, 4), ("factory", "arm", 0x2100, 4),
                     ("factory", "thumb", 0x1100, 0), ("other", "arm", 0x1100, 4)):
            with self.subTest(item=item), self.assertRaises(ValueError):
                target.audit(image(), [item])
        with self.assertRaises(ValueError):
            target.audit(image(), [("factory", "arm", 0x1100, 4)] * 2)

    def test_relocated_instruction_not_used(self):
        raw = bytearray(image())
        struct.pack_into("<I", raw, 0x20c, 32)
        struct.pack_into("<II", raw, 0x418, 0x1100, 23)
        report = target.audit(bytes(raw), [("factory", "arm", 0x1100, 4)])
        self.assertEqual(report["code_ranges"][0]["literal_load_clues"], [])


if __name__ == "__main__":
    unittest.main()
