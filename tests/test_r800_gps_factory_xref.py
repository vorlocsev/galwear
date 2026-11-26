"""Synthetic SYSV dynamic symbol and factory range tests."""
from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "build"))
import r800_gps_factory_xref as target
from test_r800_gps_interface_xref import image


def fixture(isa="arm", value=None, size=None, info=0x12, other=0, section=1,
            duplicate=False, extra=(), head=1, chain=0):
    raw = bytearray(image(isa))
    if value is None:
        value = 0x1101 if isa == "thumb" else 0x1100
    if size is None:
        size = 2 if isa == "thumb" else 4
    strings = b"\0" + target.FACTORY + b"\0"
    count = 3 if duplicate else 2
    tags = [(17, 0x2200), (18, 24), (19, 8), (4, 0x2240),
            (5, 0x2280), (10, len(strings)), (6, 0x22c0), (11, 16), *extra, (0, 0)]
    for i, pair in enumerate(tags):
        struct.pack_into("<II", raw, 0x200 + 8*i, *pair)
    struct.pack_into("<II", raw, 0x440, 1, count)
    struct.pack_into("<III", raw, 0x448, head, 0, chain)
    raw[0x480:0x480 + len(strings)] = strings
    for i in range(1, count):
        struct.pack_into("<IIIBBH", raw, 0x4c0 + 16*i, 1, value, size, info, other, section)
    return bytes(raw)


class FactoryTests(unittest.TestCase):
    def test_arm_thumb_auto_xref(self):
        for isa in ("arm", "thumb"):
            with self.subTest(isa=isa):
                report = target.audit(fixture(isa))
                self.assertEqual(report["factory_symbol"]["isa"], isa)
                self.assertEqual(report["factory_symbol"]["start_va"], 0x1100)
                self.assertEqual(report["code_ranges"][0]["literal_load_clues"][0]["table_va"], 0x2100)
                self.assertFalse(report["function_boundaries_verified"])
                self.assertFalse(report["safe_to_flash"])
                self.assertIsNone(report["selected_abi"])

    def test_invalid_symbol_type_visibility_section(self):
        for kwargs in ({"info": 0x11}, {"info": 2}, {"other": 2}, {"section": 0}, {"section": 0xfff1}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                target.audit(fixture(**kwargs))

    def test_bad_range(self):
        for kwargs in ({"size": 0}, {"size": 65540}, {"size": 2}, {"value": 0x2100}, {"value": 0x1102}, {"size": 0x200}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                target.audit(fixture(**kwargs))

    def test_duplicate_and_missing_name(self):
        with self.assertRaises(ValueError):
            target.audit(fixture(duplicate=True))
        raw = bytearray(fixture())
        raw[0x481] = ord("x")
        with self.assertRaises(ValueError):
            target.audit(bytes(raw))

    def test_unreachable_and_cyclic_hash(self):
        for kwargs in ({"head": 0}, {"chain": 1}, {"head": 2}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                target.audit(fixture(**kwargs))

    def test_versioned_and_duplicate_tags_rejected(self):
        for extra in ([(0x6ffffff0, 0x2300)], [(6, 0x22c0)]):
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                target.audit(fixture(extra=extra))

    def test_missing_sysv_hash(self):
        raw = bytearray(fixture())
        struct.pack_into("<I", raw, 0x218, 0x6ffffef5)
        with self.assertRaisesRegex(ValueError, "SYSV hash required"):
            target.audit(bytes(raw))


if __name__ == "__main__":
    unittest.main()
