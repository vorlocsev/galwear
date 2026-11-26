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



def gnu_fixture(both=False, **kwargs):
    raw = bytearray(fixture(extra=[(0x6ffffef5, 0x2320)] if both else [], **kwargs))
    if not both:
        struct.pack_into("<II", raw, 0x218, 0x6ffffef5, 0x2320)
    h = 5381
    for byte in target.FACTORY:
        h = (h * 33 + byte) & 0xffffffff
    bloom = (1 << (h % 32)) | (1 << ((h >> 5) % 32))
    struct.pack_into("<7I", raw, 0x520, 1, 1, 1, 5, bloom, 1, h | 1)
    return bytes(raw)


def version_fixture(hidden=False, duplicate=False, no_definition=False):
    raw = bytearray(fixture(duplicate=duplicate, chain=2 if duplicate else 0,
                            extra=[(0x6ffffff0, 0x2340)] +
                            ([] if no_definition else [(0x6ffffffc, 0x2350),
                                                       (0x6ffffffd, 1)])))
    version = b"GPS_1.0\0"
    offset = len(target.FACTORY) + 2
    raw[0x480 + offset:0x480 + offset + len(version)] = version
    struct.pack_into("<I", raw, 0x22c, offset + len(version))
    struct.pack_into("<3H", raw, 0x540, 0, 0x8002 if hidden else 2, 2)
    struct.pack_into("<HHHHIII", raw, 0x550, 1, 0, 2, 1,
                     target.elf_hash(version[:-1]), 20, 0)
    struct.pack_into("<II", raw, 0x564, offset, 0)
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
        with self.assertRaises(ValueError):
            target.audit(bytes(raw))


    def test_gnu_and_dual_hash(self):
        for both, kind in ((False, "GNU"), (True, "SYSV_AND_GNU")):
            with self.subTest(both=both):
                report = target.audit(gnu_fixture(both))
                self.assertEqual(report["factory_symbol"]["hash_kind"], kind)
                self.assertEqual(report["factory_symbol"]["start_va"], 0x1100)
                self.assertEqual(report["code_ranges"][0]["literal_load_clues"][0]["table_va"], 0x2100)

    def test_gnu_bloom_chain_and_head_rejected(self):
        for offset, value in ((0x530, 0), (0x534, 0), (0x538, 1)):
            with self.subTest(offset=offset):
                raw = bytearray(gnu_fixture())
                struct.pack_into("<I", raw, offset, value)
                with self.assertRaises(ValueError):
                    target.audit(bytes(raw))

    def test_dual_hash_sysv_lookup_disagreement(self):
        raw = bytearray(gnu_fixture(True))
        struct.pack_into("<I", raw, 0x448, 0)
        with self.assertRaises(ValueError):
            target.audit(bytes(raw))

    def test_versioned_default_export(self):
        report = target.audit(version_fixture())
        self.assertEqual(report["factory_symbol"]["symbol_version"], "GPS_1.0")
        self.assertTrue(report["factory_symbol"]["default_visible_candidate"])
        self.assertFalse(report["factory_signature_verified"])

    def test_hidden_and_unknown_versions_rejected(self):
        for raw in (version_fixture(hidden=True), version_fixture(no_definition=True)):
            with self.subTest(raw=raw[0x540:0x546]), self.assertRaises(ValueError):
                target.audit(raw)

    def test_hidden_variant_does_not_replace_default(self):
        report = target.audit(version_fixture(hidden=True, duplicate=True))
        self.assertEqual(report["factory_symbol"]["symbol_index"], 2)

    def test_multiple_default_versions_rejected(self):
        with self.assertRaises(ValueError):
            target.audit(version_fixture(duplicate=True))


if __name__ == "__main__":
    unittest.main()
