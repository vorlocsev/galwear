"""Synthetic ELF32 files, no ARM execution or real donor library."""
from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "build"))
import r800_gps_interface_table as target


def fixture(layout="xtra", relocs=None, words=None, extra=(), code_flags=5):
    raw = bytearray(0x600)
    raw[:7] = b"\x7fELF\x01\x01\x01"
    struct.pack_into("<HHIIIIIHHH", raw, 16, 3, 40, 1, 0, 52, 0,
                     0x05000000, 52, 32, 3)
    for i, ph in enumerate(((1, 0, 0x1000, 0, 0x200, 0x200, code_flags, 1),
                            (1, 0x200, 0x2000, 0, 0x400, 0x400, 6, 1),
                            (2, 0x200, 0x2000, 0, 0x80, 0x80, 6, 4))):
        struct.pack_into("<8I", raw, 52 + i * 32, *ph)
    count = len(target.LAYOUTS[layout])
    if words is None:
        words = [4 * (count + 1)] + [0x1100 + (i % 2) for i in range(count)]
    if relocs is None:
        relocs = [(0x2104 + i * 4, 23) for i in range(count)]
    tags = [(17, 0x2200), (18, 8 * len(relocs)), (19, 8), *extra, (0, 0)]
    for i, pair in enumerate(tags):
        struct.pack_into("<II", raw, 0x200 + i * 8, *pair)
    for i, pair in enumerate(relocs):
        struct.pack_into("<II", raw, 0x400 + i * 8, *pair)
    struct.pack_into("<" + "I" * len(words), raw, 0x300, *words)
    return bytes(raw)


class TableTests(unittest.TestCase):
    def test_relative_arm_thumb(self):
        report = target.audit(fixture(), 0x2100, "xtra")
        self.assertEqual([(x["target_va"], x["isa"]) for x in report["entries"]],
                         [(0x1100, "arm"), (0x1100, "thumb")])
        self.assertFalse(report["safe_to_flash"])
        self.assertIsNone(report["selected_abi"])

    def test_gps_layout(self):
        report = target.audit(fixture("gps"), 0x2100, "gps")
        self.assertEqual(report["declared_size"], 40)
        self.assertEqual(report["entries"][-1]["field"], "get_extension")
        self.assertEqual(report["entries"][-1]["slot_va"], 0x2124)

    def test_raw_and_symbolic_words_unresolved(self):
        report = target.audit(fixture(relocs=[(0x2108, (1 << 8) | 2)]), 0x2100, "xtra")
        self.assertEqual([x["status"] for x in report["entries"]], ["UNRESOLVED"] * 2)

    def test_nonexecutable_or_unaligned_target(self):
        for raw in (fixture(words=[12, 0x2100, 0x1102]), fixture(code_flags=7)):
            with self.subTest(raw=raw[:16]):
                report = target.audit(raw, 0x2100, "xtra")
                self.assertEqual([x["status"] for x in report["entries"]], ["UNRESOLVED"] * 2)

    def test_bad_relocations(self):
        for relocs in ([(0x2104, 23), (0x2104, 23)], [(0x2104, 0x117)],
                       [(0x2105, 23)], [(0x2104, 160)], [(0x2100, 23)]):
            with self.subTest(relocs=relocs), self.assertRaises(ValueError):
                target.audit(fixture(relocs=relocs), 0x2100, "xtra")

    def test_unsupported_encoding(self):
        for tag in (7, 36, 0x6000000f, 0x6fffe000):
            with self.subTest(tag=tag), self.assertRaises(ValueError):
                target.audit(fixture(extra=[(tag, 0)]), 0x2100, "xtra")

    def test_bad_table(self):
        for address, raw in ((0x2101, fixture()), (0x1100, fixture()),
                             (0x2100, fixture(words=[8, 0x1100, 0x1101])),
                             (0x2100, fixture(words=[4096, 0x1100, 0x1101]))):
            with self.subTest(address=address), self.assertRaises(ValueError):
                target.audit(raw, address, "xtra")

    def test_null_word(self):
        report = target.audit(fixture(relocs=[], words=[12, 0, 0]), 0x2100, "xtra")
        self.assertEqual([x["status"] for x in report["entries"]], ["NULL_WORD"] * 2)


if __name__ == "__main__":
    unittest.main()
