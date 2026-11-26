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


def symbolic_fixture(typ=2, info=0x12, other=2, section=1, value=0x1101,
                     size=2, word=0, sym=1, extra=()):
    strings = b"\0local_fn\0"
    tags = [(4, 0x2240), (5, 0x2280), (10, len(strings)),
            (6, 0x22c0), (11, 16), *extra]
    raw = bytearray(fixture(relocs=[(0x2104, 23), (0x2108, (sym << 8) | typ)],
                            words=[12, 0x1100, word], extra=tags))
    struct.pack_into("<5I", raw, 0x440, 1, 2, 1, 0, 0)
    raw[0x480:0x480 + len(strings)] = strings
    struct.pack_into("<IIIBBH", raw, 0x4d0, 1, value, size, info, other, section)
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


    def test_discover_exact_layouts(self):
        for layout in ("gps", "xtra"):
            with self.subTest(layout=layout):
                report = target.discover(fixture(layout))
                self.assertEqual(report["candidate_count"], 1)
                self.assertEqual(report["candidates"][0]["layout_assumption"], layout)
                self.assertEqual(report["candidates"][0]["table_va"], 0x2100)
                self.assertFalse(report["table_identity_verified"])
                self.assertFalse(report["discovery_complete"])
                self.assertFalse(report["safe_to_flash"])
                self.assertIsNone(report["selected_abi"])

    def test_discover_multiple_candidates(self):
        raw = bytearray(fixture(relocs=[(0x2104, 23), (0x2108, 23),
                                        (0x2124, 23), (0x2128, 23)]))
        struct.pack_into("<III", raw, 0x320, 12, 0x1100, 0x1101)
        report = target.discover(bytes(raw))
        self.assertEqual([r["table_va"] for r in report["candidates"]], [0x2100, 0x2120])

    def test_discover_rejects_nonexact_size(self):
        raw = fixture(words=[16, 0x1100, 0x1101])
        self.assertEqual(target.audit(raw, 0x2100, "xtra")["declared_size"], 16)
        self.assertEqual(target.discover(raw)["candidate_count"], 0)

    def test_discover_rejects_missing_or_symbolic_reloc(self):
        for relocs in ([], [(0x2104, 23)], [(0x2104, 23), (0x2108, 258)]):
            with self.subTest(relocs=relocs):
                self.assertEqual(target.discover(fixture(relocs=relocs))["candidate_count"], 0)

    def test_discover_rejects_invalid_code_targets(self):
        for words in ([12, 0x1100, 0], [12, 0x1100, 0x2100], [12, 0x1100, 0x1102]):
            with self.subTest(words=words):
                self.assertEqual(target.discover(fixture(words=words))["candidate_count"], 0)

    def test_discover_rejects_invalid_relocation_table(self):
        with self.assertRaises(ValueError):
            target.discover(fixture(relocs=[(0x2104, 23), (0x2104, 23)]))

    def test_discover_budget(self):
        from unittest.mock import patch
        with patch.object(target, "MAX_CANDIDATES", 0), self.assertRaises(ValueError):
            target.discover(fixture())


    def test_symbolic_relocations(self):
        for typ in (2, 21, 22):
            with self.subTest(typ=typ):
                raw = symbolic_fixture(typ=typ)
                self.assertEqual(target.discover(raw)["candidate_count"], 0)
                report = target.discover(raw, symbolic=True)
                self.assertEqual(report["candidate_count"], 1)
                entry = report["candidates"][0]["entries"][1]
                self.assertEqual((entry["target_va"], entry["isa"]), (0x1100, "thumb"))
                self.assertEqual(entry["status"], "SYMBOLIC_EXECUTABLE_CANDIDATE")
                self.assertEqual(entry["symbolic_evidence"]["relocation_type"], typ)
                self.assertFalse(report["safe_to_flash"])
                self.assertFalse(report["candidates"][0]["relocations_applied"])

    def test_symbolic_binding_visibility(self):
        for info, other, accepted in ((2, 0, True), (0x12, 2, True), (0x12, 3, True),
                                      (0x22, 2, True), (0x12, 0, False), (0x22, 0, False)):
            with self.subTest(info=info, other=other):
                report = target.discover(symbolic_fixture(info=info, other=other), symbolic=True)
                self.assertEqual(report["candidate_count"], int(accepted))

    def test_symbolic_unsupported_definition(self):
        for kwargs in ({"section": 0}, {"section": 0xfff1}, {"info": 0x11},
                       {"info": 0x1a}, {"size": 0}, {"value": 0x2100}, {"value": 0x1102}):
            with self.subTest(kwargs=kwargs):
                report = target.discover(symbolic_fixture(**kwargs), symbolic=True)
                self.assertEqual(report["candidate_count"], 0)

    def test_nonzero_addend_not_resolved(self):
        for typ in (2, 21, 22):
            with self.subTest(typ=typ):
                report = target.audit(symbolic_fixture(typ=typ, word=4), 0x2100, "xtra", symbolic=True)
                self.assertEqual(report["entries"][1]["status"], "UNRESOLVED")

    def test_symbol_index_bounds(self):
        with self.assertRaisesRegex(ValueError, "symbol index"):
            target.discover(symbolic_fixture(sym=2), symbolic=True)

    def test_unsupported_symbol_inventory(self):
        for extra in ([(0x6ffffff0, 0x2300)], [(0x6ffffef5, 0x2300)]):
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                target.discover(symbolic_fixture(extra=extra), symbolic=True)
        with self.assertRaises(ValueError):
            target.discover(fixture(relocs=[(0x2104, 23), (0x2108, 258)]), symbolic=True)

    def test_symbolic_bad_hash_chain(self):
        raw = bytearray(symbolic_fixture())
        struct.pack_into("<I", raw, 0x450, 1)
        with self.assertRaisesRegex(ValueError, "Cyclic"):
            target.discover(bytes(raw), symbolic=True)


class LoadMappingTests(unittest.TestCase):
    @staticmethod
    def add_load(raw, va, fs, ms, flags, off=0):
        raw = bytearray(raw)
        struct.pack_into("<H", raw, 44, 4)
        struct.pack_into("<8I", raw, 52 + 3 * 32,
                         1, off, va, 0, fs, ms, flags, 1)
        return bytes(raw)

    def test_partial_full_and_bss_overlap(self):
        for va, fs, ms, flags in ((0x1102, 2, 2, 6),
                                  (0x1100, 4, 4, 5),
                                  (0x10f0, 0, 0x40, 6),
                                  (0x10fc, 4, 8, 4)):
            with self.subTest(va=va, fs=fs, ms=ms, flags=flags):
                raw = self.add_load(fixture(), va, fs, ms, flags)
                mapping, _ = target.parse_elf(raw)
                with self.assertRaisesRegex(ValueError, "not uniquely mapped"):
                    mapping(0x1100, 4)
                self.assertEqual(target.discover(raw)["candidate_count"], 0)

    def test_overlap_with_symbolic_function_extent(self):
        raw = symbolic_fixture(value=0x1100, size=12)
        raw = self.add_load(raw, 0x1108, 0, 4, 6)
        report = target.audit(raw, 0x2100, "xtra", symbolic=True)
        self.assertEqual(report["entries"][1]["status"], "UNRESOLVED")
        self.assertEqual(target.discover(raw, symbolic=True)["candidate_count"], 0)
        self.assertFalse(report["safe_to_flash"])

    def test_partial_relocation_target_overlap(self):
        for fs in (0, 2):
            with self.subTest(fs=fs):
                raw = self.add_load(fixture(), 0x2106, fs, 2, 4)
                with self.assertRaisesRegex(ValueError, "ambiguously mapped"):
                    target.parse_elf(raw)

    def test_dynamic_table_overlap(self):
        raw = self.add_load(fixture(), 0x207c, 0, 4, 4)
        with self.assertRaisesRegex(ValueError, "not uniquely mapped"):
            target.parse_elf(raw)

    def test_adjacent_and_empty_memory_extents(self):
        for va, fs, ms in ((0x1200, 4, 4), (0x1100, 0, 0)):
            with self.subTest(va=va, fs=fs, ms=ms):
                raw = self.add_load(fixture(), va, fs, ms, 6)
                mapping, _ = target.parse_elf(raw)
                self.assertEqual(mapping(0x1100, 4), (0x100, 5))
                self.assertEqual(target.discover(raw)["candidate_count"], 1)

    def test_unique_bss_relocation_is_not_file_backed(self):
        raw = self.add_load(fixture(relocs=[(0x2104, 23), (0x2108, 23),
                                           (0x3000, 23)]), 0x3000, 0, 16, 6)
        mapping, relocations = target.parse_elf(raw)
        self.assertEqual(relocations[0x3000], (23, 0))
        with self.assertRaisesRegex(ValueError, "not uniquely file-backed"):
            mapping(0x3000, 4)
        self.assertEqual(target.discover(raw)["candidate_count"], 1)


class LoadAlignmentTests(unittest.TestCase):
    @staticmethod
    def page_fixture():
        # Move the data segment to an aligned file offset without changing VAs.
        raw = bytearray(fixture())
        raw = raw[:0x200] + bytearray(0xe00) + raw[0x200:]
        struct.pack_into("<I", raw, 52 + 32 + 4, 0x1000)
        struct.pack_into("<I", raw, 52 + 64 + 4, 0x1000)
        return raw

    def test_alignment_power_and_congruence(self):
        for align in (0, 1, 2, 0x200, 0x1000):
            with self.subTest(align=align):
                raw = self.page_fixture()
                for index in (0, 1):
                    struct.pack_into("<I", raw, 52 + index * 32 + 28, align)
                self.assertEqual(target.discover(bytes(raw))["candidate_count"], 1)
        for align in (3, 0x300, 0x2000):
            with self.subTest(align=align):
                raw = self.page_fixture()
                struct.pack_into("<I", raw, 52 + 32 + 28, align)
                with self.assertRaisesRegex(ValueError, "Invalid PT_LOAD alignment"):
                    target.discover(bytes(raw))

    def test_default_and_strict_page_congruence(self):
        self.assertFalse(target.discover(fixture())["strict_4k_page_review"])
        with self.assertRaisesRegex(ValueError, "page offset mismatch"):
            target.discover(fixture(), strict_pages=True)
        raw = bytes(self.page_fixture())
        report = target.discover(raw, strict_pages=True)
        self.assertEqual(report["candidate_count"], 1)
        self.assertTrue(report["strict_4k_page_review"])
        self.assertFalse(report["safe_to_flash"])
        self.assertTrue(target.audit(raw, 0x2100, "xtra",
                                     strict_pages=True)["strict_4k_page_review"])

    def test_shared_page_even_without_byte_overlap(self):
        for flags, filesz in ((5, 4), (6, 4), (6, 0)):
            with self.subTest(flags=flags, filesz=filesz):
                raw = LoadMappingTests.add_load(self.page_fixture(),
                                               0x1200, filesz, 4, flags, off=0x200)
                self.assertEqual(target.discover(raw)["candidate_count"], 1)
                with self.assertRaisesRegex(ValueError, "shared memory page"):
                    target.discover(raw, strict_pages=True)

    def test_adjacent_page_and_empty_extent(self):
        for va, off, ms in ((0x3000, 0, 4), (0x1100, 0x100, 0)):
            with self.subTest(va=va, ms=ms):
                raw = LoadMappingTests.add_load(self.page_fixture(),
                                               va, 0, ms, 6, off=off)
                self.assertEqual(target.discover(raw, strict_pages=True)["candidate_count"], 1)


if __name__ == "__main__":
    unittest.main()
