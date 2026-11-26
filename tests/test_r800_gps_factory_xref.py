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


def call_fixture(*, second_thumb=False, first_info=0x12, first_other=2,
                 second_value=None, second_size=None, relocated=False):
    raw = bytearray(fixture(size=28))
    strings = b"\0" + target.FACTORY + b"\0first\0second\0"
    first_name = len(target.FACTORY) + 2
    second_name = first_name + 6
    raw[0x480:0x480 + len(strings)] = strings
    struct.pack_into("<I", raw, 0x22c, len(strings))
    struct.pack_into("<7I", raw, 0x440, 1, 4, 1, 0, 0, 0, 0)
    struct.pack_into("<IIIBBH", raw, 0x4e0, first_name, 0x11c0, 12, first_info, first_other, 1)
    struct.pack_into("<IIIBBH", raw, 0x4f0, second_name,
                     (0x11e1 if second_thumb else 0x11e0) if second_value is None else second_value,
                     (2 if second_thumb else 4) if second_size is None else second_size, 0x02, 0, 1)
    struct.pack_into("<7I", raw, 0x100, 0xe3000070, 0xe3400000, 0xe08f0000, 0xe92d4010,
                     0xeb00002a, 0xe5901000, 0xe8bd8010)
    struct.pack_into("<3I", raw, 0x1c0, 0xe92d4010,
                     0xfa000005 if second_thumb else 0xeb000005, 0xe8bd8010)
    if second_thumb:
        struct.pack_into("<H", raw, 0x1e0, 0x4770)
    else:
        struct.pack_into("<I", raw, 0x1e0, 0xe12fff1e)
    if relocated:
        struct.pack_into("<I", raw, 0x20c, 32)
        struct.pack_into("<II", raw, 0x418, 0x1110, 23)
    return bytes(raw)


def extended_call_fixture(*, gnu=False, both=False, version=None):
    raw = bytearray(call_fixture(first_other=3))
    # Local symbol first, then protected first callee and visible factory.
    a, b = raw[0x4d0:0x4e0], raw[0x4f0:0x500]
    raw[0x4d0:0x4e0], raw[0x4f0:0x500] = b, a
    struct.pack_into("<I", raw, 0x448, 3)
    tags = [(17, 0x2200), (18, 24), (19, 8), (5, 0x2280), (6, 0x22c0), (11, 16)]
    strings = b"\0" + target.FACTORY + b"\0first\0second\0"
    if not gnu or both:
        tags.append((4, 0x2240))
    if gnu:
        tags.append((0x6ffffef5, 0x2320))
        hashes = []
        bloom = 0
        for name in (b"first", target.FACTORY):
            h = 5381
            for byte in name:
                h = (h * 33 + byte) & 0xffffffff
            hashes.append(h)
            bloom |= (1 << (h % 32)) | (1 << ((h >> 5) % 32))
        struct.pack_into("<8I", raw, 0x520, 1, 2, 1, 5, bloom, 2, hashes[0] & ~1, hashes[1] | 1)
    if version is not None:
        index = len(strings)
        strings += b"GPS_1.0\0"
        tags += [(0x6ffffff0, 0x2340), (0x6ffffffc, 0x2350), (0x6ffffffd, 1)]
        struct.pack_into("<4H", raw, 0x540, 0, 0, version, 2)
        struct.pack_into("<HHHHIII", raw, 0x550, 1, 0, 2, 1, target.elf_hash(b"GPS_1.0"), 20, 0)
        struct.pack_into("<II", raw, 0x564, index, 0)
    tags += [(10, len(strings)), (0, 0)]
    raw[0x200:0x280] = bytes(0x80)
    for i, pair in enumerate(tags):
        struct.pack_into("<II", raw, 0x200 + 8*i, *pair)
    raw[0x480:0x480 + len(strings)] = strings
    return bytes(raw)


class AutomaticCalleeTests(unittest.TestCase):
    def test_opt_in_and_depth(self):
        raw = call_fixture()
        self.assertEqual(target.audit(raw)["auto_callee_candidates"], [])
        shallow = target.audit(raw, auto_callees=True)
        self.assertEqual([r["symbol_name"] for r in shallow["auto_callee_candidates"]], ["first"])
        self.assertEqual(shallow["code_ranges"][0]["pic_flow"]["events"], [])
        deep = target.audit(raw, auto_callees=True, callee_depth=2)
        self.assertEqual([r["symbol_name"] for r in deep["auto_callee_candidates"]], ["first", "second"])
        self.assertEqual(deep["code_ranges"][0]["pic_flow"]["events"][0]["table_va"], 0x2100)
        self.assertFalse(deep["safe_to_flash"])

    def test_interworking(self):
        report = target.audit(call_fixture(second_thumb=True), auto_callees=True, callee_depth=2)
        self.assertEqual(report["auto_callee_candidates"][1]["isa"], "thumb")
        self.assertEqual(report["code_ranges"][0]["pic_flow"]["events"][0]["table_va"], 0x2100)

    def test_preemptible_and_ifunc_excluded(self):
        for kwargs in ({"first_other": 0}, {"first_info": 0x1a}):
            with self.subTest(kwargs=kwargs):
                report = target.audit(call_fixture(**kwargs), auto_callees=True, callee_depth=2)
                self.assertEqual(report["auto_callee_candidates"], [])
                self.assertEqual(report["code_ranges"][0]["pic_flow"]["events"], [])

    def test_overlapping_and_zero_size_alias_excluded(self):
        for value, size in ((0x11c0, 4), (0x11c4, 0), (0x11bc, 8)):
            with self.subTest(value=value, size=size):
                report = target.audit(call_fixture(second_value=value, second_size=size), auto_callees=True, callee_depth=2)
                self.assertEqual(report["auto_callee_candidates"], [])

    def test_relocated_call_not_scanned(self):
        report = target.audit(call_fixture(relocated=True), auto_callees=True, callee_depth=2)
        self.assertEqual(report["auto_callee_candidates"], [])

    def test_extended_inventory_without_callees(self):
        for raw in (gnu_fixture(), gnu_fixture(True), version_fixture()):
            with self.subTest(raw=raw[0x218:0x220]):
                report = target.audit(raw, auto_callees=True)
                self.assertEqual(report["auto_callee_candidates"], [])

    def test_gnu_and_dual_auto_callees(self):
        for both in (False, True):
            report = target.audit(extended_call_fixture(gnu=True, both=both), auto_callees=True, callee_depth=2)
            self.assertEqual([r["symbol_name"] for r in report["auto_callee_candidates"]], ["first", "second"])
            self.assertEqual(report["code_ranges"][0]["pic_flow"]["events"][0]["table_va"], 0x2100)

    def test_versioned_callee_hidden_and_default(self):
        for hidden in (False, True):
            report = target.audit(extended_call_fixture(gnu=True, version=0x8002 if hidden else 2), auto_callees=True, callee_depth=2)
            first = report["auto_callee_candidates"][0]
            self.assertEqual(first["symbol_version"], "GPS_1.0")
            self.assertEqual(first["version_hidden"], hidden)
            self.assertEqual(len(report["code_ranges"][0]["pic_flow"]["events"]), 1)

    def test_version_invalid_local_and_nonlocal(self):
        for version in (0, 0x8001):
            report = target.audit(extended_call_fixture(version=version), auto_callees=True, callee_depth=2)
            self.assertEqual(report["auto_callee_candidates"], [])
        raw = bytearray(extended_call_fixture(version=2))
        struct.pack_into("<H", raw, 0x542, 1)
        report = target.audit(bytes(raw), auto_callees=True, callee_depth=2)
        self.assertEqual([r["symbol_name"] for r in report["auto_callee_candidates"]], ["first"])
        self.assertEqual(report["code_ranges"][0]["pic_flow"]["events"], [])

    def test_unknown_version_and_corrupt_gnu_rejected(self):
        raw = bytearray(extended_call_fixture(version=2))
        struct.pack_into("<H", raw, 0x544, 3)
        with self.assertRaises(ValueError):
            target.audit(bytes(raw), auto_callees=True)
        raw = bytearray(extended_call_fixture(gnu=True))
        struct.pack_into("<I", raw, 0x530, 0)
        with self.assertRaises(ValueError):
            target.audit(bytes(raw), auto_callees=True)

    def test_depth_validation(self):
        for depth in (0, 5, True):
            with self.subTest(depth=depth), self.assertRaises(ValueError):
                target.audit(call_fixture(), auto_callees=True, callee_depth=depth)
        with self.assertRaises(ValueError):
            target.audit(call_fixture(), callee_depth=2)


def static_fixture(*, thumb=False, alias=False, flags=6, fileoff=0, extent=12, binding=0x02):
    raw = bytearray(call_fixture(second_thumb=thumb))
    # First callee absent from dynsym; the second is duplicated in symtab.
    raw[0x4ec] = 0x10
    raw.extend(bytes(0x200))
    struct.pack_into("<I", raw, 32, 0x600)
    struct.pack_into("<HHH", raw, 46, 40, 4, 0)
    strings = b"\0first\0second\0alias\0"
    raw[0x6a0:0x6a0+len(strings)] = strings
    n = 4 if alias else 3
    struct.pack_into("<10I", raw, 0x628, 0, 1, flags, 0x1000, fileoff, 0x200, 0, 0, 4, 0)
    struct.pack_into("<10I", raw, 0x650, 0, 3, 0, 0, 0x6a0, len(strings), 0, 0, 1, 0)
    struct.pack_into("<10I", raw, 0x678, 0, 2, 0, 0, 0x700, 16*n, 2, n, 4, 16)
    struct.pack_into("<IIIBBH", raw, 0x710, 1, 0x11c0, extent, binding, 0, 1)
    struct.pack_into("<IIIBBH", raw, 0x720, 7, 0x11e1 if thumb else 0x11e0, 2 if thumb else 4, 2, 0, 1)
    if alias:
        struct.pack_into("<IIIBBH", raw, 0x730, 14, 0x11c4, 4, 2, 0, 1)
    return bytes(raw)


class StaticCalleeTests(unittest.TestCase):
    def analyze(self, raw):
        return target.audit(raw, auto_callees=True, callee_depth=2, static_symbols=True)

    def test_internal_callee_and_exact_dynamic_duplicate(self):
        for thumb in (False, True):
            with self.subTest(thumb=thumb):
                raw = static_fixture(thumb=thumb)
                self.assertEqual(target.audit(raw, auto_callees=True, callee_depth=2)["auto_callee_candidates"], [])
                report = self.analyze(raw)
                first, second = report["auto_callee_candidates"]
                self.assertEqual(first["symbol_source"], "SHT_SYMTAB")
                self.assertEqual(first["section_index"], 1)
                self.assertEqual(second["isa"], "thumb" if thumb else "arm")
                self.assertEqual(report["code_ranges"][0]["pic_flow"]["events"][0]["table_va"], 0x2100)
                self.assertFalse(report["safe_to_flash"])

    def test_stripped_fallback_and_opt_in(self):
        report = self.analyze(call_fixture())
        self.assertEqual(len(report["auto_callee_candidates"]), 2)
        with self.assertRaises(ValueError):
            target.audit(static_fixture(), static_symbols=True)

    def test_ambiguous_static_alias(self):
        self.assertEqual(self.analyze(static_fixture(alias=True))["auto_callee_candidates"], [])

    def test_section_flags_mapping_and_extent(self):
        for kwargs in ({"flags": 7}, {"flags": 2}, {"fileoff": 4}, {"extent": 0}, {"extent": 0x100}):
            with self.subTest(kwargs=kwargs):
                self.assertEqual(self.analyze(static_fixture(**kwargs))["auto_callee_candidates"], [])

    def test_bad_section_table_and_symbol_table(self):
        for offset, fmt, value in ((32, "I", 0x7f0), (46, "H", 39), (48, "H", 0),
                                   (0x690, "I", 4), (0x69c, "I", 8), (0x68c, "I", 0xffff)):
            with self.subTest(offset=offset):
                raw = bytearray(static_fixture())
                struct.pack_into("<" + fmt, raw, offset, value)
                with self.assertRaises(ValueError):
                    self.analyze(bytes(raw))

    def test_bad_name_partition_and_section_index(self):
        for offset, fmt, value in ((0x710, "I", 0xffff), (0x71c, "B", 0x12), (0x71e, "H", 4)):
            with self.subTest(offset=offset):
                raw = bytearray(static_fixture())
                struct.pack_into("<" + fmt, raw, offset, value)
                with self.assertRaises(ValueError):
                    self.analyze(bytes(raw))

    def test_static_only_global_function_not_promoted(self):
        raw = bytearray(static_fixture())
        # Put both entries in the global partition, with no dynsym duplicate.
        struct.pack_into("<I", raw, 0x694, 1)
        raw[0x71c] = 0x12
        raw[0x72c] = 0x12
        self.assertEqual(self.analyze(bytes(raw))["auto_callee_candidates"], [])


def mapping_fixture(markers, *, thumb=False):
    raw = bytearray(static_fixture(thumb=thumb))
    strings = bytearray(b"\0first\0second\0alias\0")
    for i, marker in enumerate(markers, 3):
        label, value, *extra = marker
        info, section, extent = extra or (0, 1, 0)
        name = len(strings)
        strings.extend(label + b"\0")
        struct.pack_into("<IIIBBH", raw, 0x700 + 16*i, name, value, extent, info, 0, section)
    raw[0x6a0:0x6a0+len(strings)] = strings
    struct.pack_into("<I", raw, 0x664, len(strings))
    struct.pack_into("<I", raw, 0x68c, 16*(3+len(markers)))
    struct.pack_into("<I", raw, 0x694, 3+len(markers))
    return bytes(raw)


class MappingSymbolTests(unittest.TestCase):
    def analyze(self, raw):
        return target.audit(raw, auto_callees=True, callee_depth=2, static_symbols=True, mapping_symbols=True)

    def test_uniform_arm_and_thumb(self):
        for thumb in (False, True):
            with self.subTest(thumb=thumb):
                raw = mapping_fixture([(b"$a.0", 0x1100), (b"$t.1" if thumb else b"$a.1", 0x11e0)], thumb=thumb)
                report = self.analyze(raw)
                self.assertEqual(report["factory_symbol"]["mapping_symbol_coverage"], "UNIFORM_ISA_METADATA_ONLY")
                self.assertEqual(len(report["auto_callee_candidates"]), 2)
                self.assertEqual(report["code_ranges"][0]["pic_flow"]["events"][0]["table_va"], 0x2100)
                self.assertFalse(report["function_boundaries_verified"])

    def test_data_and_mode_change_in_factory(self):
        for marker in (b"$d", b"$t"):
            raw = mapping_fixture([(b"$a", 0x1100), (marker, 0x1110)])
            with self.assertRaisesRegex(ValueError, "mapping range"):
                self.analyze(raw)

    def test_data_in_callee_not_analyzed(self):
        raw = mapping_fixture([(b"$a", 0x1100), (b"$d.1", 0x11c4), (b"$a.2", 0x11e0)])
        with self.assertRaisesRegex(ValueError, "mapping range"):
            self.analyze(raw)

    def test_marker_at_exclusive_end(self):
        raw = mapping_fixture([(b"$a", 0x1100), (b"$d", 0x111c), (b"$a.1", 0x11c0)])
        self.assertEqual(len(self.analyze(raw)["auto_callee_candidates"]), 2)

    def test_missing_coverage_and_opt_in(self):
        for raw in (call_fixture(), static_fixture(), mapping_fixture([(b"$a", 0x1104)])):
            with self.assertRaisesRegex(ValueError, "mapping"):
                self.analyze(raw)
        with self.assertRaises(ValueError):
            target.audit(call_fixture(), auto_callees=True, mapping_symbols=True)
        self.assertFalse(target.audit(static_fixture())["mapping_symbol_mode"])

    def test_conflicting_or_malformed_markers(self):
        for markers in ([(b"$a", 0x1100), (b"$t", 0x1100)], [(b"$a", 0x1102)],
                        [(b"$t", 0x1101)], [(b"$a", 0x1200)], [(b"$a", 0x1100, 2, 1, 0)],
                        [(b"$d", 0x1100, 0, 4, 0)], [(b"$a", 0x1100, 0, 1, 4)]):
            with self.subTest(markers=markers), self.assertRaises(ValueError):
                self.analyze(mapping_fixture(markers))

    def test_wrong_section_file_mapping(self):
        raw = bytearray(mapping_fixture([(b"$a", 0x1100)]))
        struct.pack_into("<I", raw, 0x638, 4)
        with self.assertRaisesRegex(ValueError, "file-backed"):
            self.analyze(bytes(raw))

class LiteralPoolTests(unittest.TestCase):
    def analyze(self, raw):
        return target.audit(raw, auto_callees=True, callee_depth=2, static_symbols=True,
                            mapping_symbols=True, literal_pools=True)

    def arm_fixture(self, branch=0xea000001, literal=0xe59f0004):
        raw = bytearray(mapping_fixture([(b"$a", 0x1100), (b"$d", 0x1108), (b"$a.1", 0x1110)]))
        # Data at 0x1108 resembles BL; only the real literal is relocated.
        struct.pack_into("<7I", raw, 0x100, literal, branch, 0xeb00002c, 0x2100,
                         0xe1a01000, 0xe12fff1e, 0xe320f000)
        struct.pack_into("<I", raw, 0x20c, 32)
        struct.pack_into("<II", raw, 0x418, 0x110c, 23)
        return bytes(raw)

    def test_arm_pool_skipped_and_literal_loaded(self):
        r = self.analyze(self.arm_fixture())
        self.assertEqual(r["factory_symbol"]["mapping_symbol_coverage"], "CODE_AND_DATA_METADATA_ONLY")
        self.assertEqual(r["auto_callee_candidates"], [])
        flow = r["code_ranges"][0]["pic_flow"]
        self.assertEqual(flow["boundaries"], [])
        self.assertEqual(flow["events"], [{"address": 0x1100, "register": "r0", "slot_va": 0x110c,
                                           "table_va": 0x2100, "kind": "RELOCATED_LITERAL_LOAD"}])

    def test_arm_branch_or_fallthrough_into_data(self):
        for branch in (0xea000000, 0xe320f000, 0x1a000001):
            flow = self.analyze(self.arm_fixture(branch))["code_ranges"][0]["pic_flow"]
            self.assertEqual(flow["events"], [])
            self.assertEqual(flow["boundaries"][0]["reason"], "edge_into_data_or_noninstruction")

    def test_literal_must_be_inside_marked_data(self):
        flow = self.analyze(self.arm_fixture(literal=0xe59f0078))["code_ranges"][0]["pic_flow"]
        self.assertEqual(flow["events"], [])
        self.assertEqual(flow["boundaries"][0]["reason"], "literal_outside_marked_data")

    def thumb_fixture(self, branch=0xe003, resume=0x4770):
        raw = bytearray(mapping_fixture([(b"$t", 0x1100), (b"$d", 0x1104), (b"$t.1", 0x110c), (b"$a", 0x111c)]))
        struct.pack_into("<I", raw, 0x4d4, 0x1101)
        struct.pack_into("<4H", raw, 0x100, 0x4801, branch, 0xbf08, 0xf000)
        struct.pack_into("<I", raw, 0x108, 0x2100)
        struct.pack_into("<8H", raw, 0x10c, resume, *([0xbf00] * 7))
        struct.pack_into("<I", raw, 0x20c, 32)
        struct.pack_into("<II", raw, 0x418, 0x1108, 23)
        return bytes(raw)

    def test_thumb_data_is_not_it_or_wide_instruction(self):
        flow = self.analyze(self.thumb_fixture())["code_ranges"][0]["pic_flow"]
        self.assertEqual(flow["boundaries"], [])
        self.assertEqual(flow["events"][0]["slot_va"], 0x1108)
        self.assertEqual(flow["events"][0]["kind"], "RELOCATED_LITERAL_LOAD")

    def test_thumb_branch_into_data_or_wide_tail(self):
        for raw in (self.thumb_fixture(branch=0xe001), self.thumb_fixture(branch=0xe004, resume=0xf240),
                    self.thumb_fixture(branch=0xbf00)):
            flow = self.analyze(raw)["code_ranges"][0]["pic_flow"]
            self.assertEqual(flow["events"], [])
            self.assertTrue(flow["boundaries"])

    def test_callee_data_pool_keeps_return_summary(self):
        raw = bytearray(mapping_fixture([(b"$a", 0x1100), (b"$d", 0x11c4), (b"$a.1", 0x11c8)]))
        struct.pack_into("<3I", raw, 0x1c0, 0xea000000, 0xeb000005, 0xe12fff1e)
        report = self.analyze(bytes(raw))
        self.assertEqual(len(report["auto_callee_candidates"]), 1)
        flow = report["code_ranges"][0]["pic_flow"]
        self.assertEqual(flow["boundaries"], [])
        self.assertEqual(flow["events"][0]["table_va"], 0x2100)

    def test_strict_mode_and_misaligned_data_unchanged(self):
        with self.assertRaises(ValueError):
            target.audit(self.arm_fixture(), auto_callees=True, static_symbols=True, mapping_symbols=True)
        with self.assertRaises(ValueError):
            target.audit(self.arm_fixture(), literal_pools=True)
        with self.assertRaises(ValueError):
            self.analyze(mapping_fixture([(b"$a", 0x1100), (b"$d", 0x1109), (b"$a.1", 0x1110)]))
        with self.assertRaises(ValueError):
            self.analyze(mapping_fixture([(b"$a", 0x1100), (b"$t", 0x1110)]))

class AutomaticCallbackTests(unittest.TestCase):
    def fixture(self, *, static=False, thumb=False, **kwargs):
        raw = bytearray(static_fixture(thumb=thumb, **kwargs) if static else call_fixture(second_thumb=thumb, **kwargs))
        struct.pack_into("<7I", raw, 0x100, 0xe3000ff0, 0xe3400000, 0xe08f0000, 0xe92d4010,
                         0xe5903004, 0xe12fff33, 0xe8bd8010)
        struct.pack_into("<II", raw, 0x304, 0x11c0, 0x11a0)
        return raw

    def analyze(self, raw, **kwargs):
        return target.audit(bytes(raw), auto_callees=True, callback_calls=True, **kwargs)

    def test_seed_and_nested_direct_call(self):
        raw = self.fixture()
        report = self.analyze(raw, callee_depth=2)
        first, second = report["auto_callee_candidates"]
        self.assertEqual(first["symbol_name"], "first")
        self.assertEqual(first["callback_slot_candidates"][0]["slot_va"], 0x2104)
        self.assertEqual(second["symbol_name"], "second")
        flow = report["code_ranges"][0]["pic_flow"]
        self.assertEqual(flow["boundaries"], [])
        self.assertEqual(flow["assumed_calls"][0]["instruction"], "BLX_REG")
        self.assertEqual(flow["assumed_calls"][0]["modeled_nested_depth"], 1)
        self.assertFalse(report["callee_discovery_complete"])
        self.assertFalse(report["safe_to_flash"])

    def test_depth_budget_and_disabled_mode(self):
        raw = self.fixture()
        shallow = self.analyze(raw)
        self.assertEqual(len(shallow["auto_callee_candidates"]), 1)
        self.assertEqual(shallow["code_ranges"][0]["pic_flow"]["assumed_calls"], [])
        disabled = target.audit(bytes(raw), auto_callees=True, callee_depth=2)
        self.assertEqual(disabled["auto_callee_candidates"], [])
        self.assertFalse(disabled["callback_call_mode"])
        with self.assertRaises(ValueError):
            target.audit(bytes(raw), callback_calls=True)

    def test_static_callback_and_nested_interworking(self):
        report = self.analyze(self.fixture(static=True, thumb=True), static_symbols=True, callee_depth=2)
        first, second = report["auto_callee_candidates"]
        self.assertEqual(first["symbol_source"], "SHT_SYMTAB")
        self.assertEqual(second["isa"], "thumb")
        self.assertEqual(report["code_ranges"][0]["pic_flow"]["boundaries"], [])

    def test_thumb_callback_seed_exact_isa(self):
        raw = self.fixture(thumb=True)
        struct.pack_into("<I", raw, 0x304, 0x11e1)
        report = self.analyze(raw)
        row, = report["auto_callee_candidates"]
        self.assertEqual((row["start_va"], row["isa"]), (0x11e0, "thumb"))
        self.assertEqual(report["code_ranges"][0]["pic_flow"]["assumed_calls"][0]["target_isa"], "thumb")
        struct.pack_into("<I", raw, 0x304, 0x11e0)
        with self.assertRaisesRegex(ValueError, "No eligible"):
            self.analyze(raw)

    def test_alias_preemptible_and_interior_excluded(self):
        for raw in (self.fixture(first_other=0), self.fixture(first_info=0x1a),
                    self.fixture(second_value=0x11c4, second_size=0), self.fixture(static=True, alias=True)):
            with self.assertRaisesRegex(ValueError, "No eligible"):
                self.analyze(raw, static_symbols=True)
        raw = self.fixture()
        struct.pack_into("<I", raw, 0x304, 0x11c4)
        with self.assertRaisesRegex(ValueError, "No eligible"):
            self.analyze(raw)

    def test_mapping_coverage_required_when_enabled(self):
        raw = bytearray(mapping_fixture([(b"$a", 0x1100), (b"$d", 0x11c4), (b"$a.1", 0x11e0)]))
        code = self.fixture()
        raw[0x100:0x11c] = code[0x100:0x11c]
        raw[0x304:0x30c] = code[0x304:0x30c]
        with self.assertRaisesRegex(ValueError, "mapping range"):
            self.analyze(raw, static_symbols=True, mapping_symbols=True)

    def test_multiple_slots_seed_once_and_not_reachability(self):
        raw = self.fixture()
        struct.pack_into("<I", raw, 0x308, 0x11c0)
        struct.pack_into("<I", raw, 0x110, 0xe12fff1e)  # No actual indirect call reached.
        report = self.analyze(raw)
        row, = report["auto_callee_candidates"]
        self.assertEqual([e["slot_va"] for e in row["callback_slot_candidates"]], [0x2104, 0x2108])
        self.assertEqual(report["code_ranges"][0]["pic_flow"]["assumed_calls"], [])

class SymbolicCallbackTests(unittest.TestCase):
    def fixture(self, *, got=False, typ=None, **kwargs):
        raw = AutomaticCallbackTests().fixture(**kwargs)
        if got:
            struct.pack_into("<I", raw, 0x304, 0x11a0)
            struct.pack_into("<I", raw, 0x110, 0xe5903040)
            struct.pack_into("<I", raw, 0x20c, 32)
            struct.pack_into("<II", raw, 0x418, 0x2140, 0x200 | (21 if typ is None else typ))
        else:
            struct.pack_into("<I", raw, 0x304, 0)
            struct.pack_into("<I", raw, 0x404, 0x200 | (2 if typ is None else typ))
        return raw

    def analyze(self, raw, **kwargs):
        return target.audit(bytes(raw), auto_callees=True, callback_calls=True, symbolic=True,
                            callee_depth=2, **kwargs)

    def test_symbolic_table_callback(self):
        raw = self.fixture()
        report = self.analyze(raw)
        self.assertEqual(report["symbolic_callback_slot_count"], 1)
        self.assertEqual(report["function_got_slot_candidate_count"], 0)
        ev = report["auto_callee_candidates"][0]["callback_slot_candidates"][0]
        self.assertEqual(ev["symbolic_evidence"]["symbol_index"], 2)
        flow = report["code_ranges"][0]["pic_flow"]
        self.assertEqual(flow["boundaries"], [])
        self.assertEqual(flow["assumed_calls"][0]["instruction"], "BLX_REG")
        self.assertFalse(report["safe_to_flash"])
        with self.assertRaisesRegex(ValueError, "No eligible"):
            target.audit(bytes(raw), auto_callees=True, callback_calls=True, callee_depth=2)

    def test_got_function_pointer(self):
        report = self.analyze(self.fixture(got=True))
        self.assertEqual(report["function_got_slot_candidate_count"], 1)
        self.assertFalse(report["got_membership_verified"])
        flow = report["code_ranges"][0]["pic_flow"]
        self.assertEqual(flow["boundaries"], [])
        self.assertEqual(flow["events"][-1]["slot_va"], 0x2140)
        self.assertEqual(flow["events"][-1]["source"], "GLOB_DAT_SLOT_CANDIDATE")
        self.assertTrue(flow["assumed_calls"][0]["callee_analyzed"])

    def test_external_preemptible_and_nonzero_addend(self):
        for raw in (self.fixture(first_other=0), self.fixture(first_info=0x1a)):
            with self.assertRaisesRegex(ValueError, "No eligible"):
                self.analyze(raw)
        for got in (False, True):
            raw = self.fixture(got=got)
            struct.pack_into("<I", raw, 0x340 if got else 0x304, 4)
            with self.assertRaisesRegex(ValueError, "No eligible"):
                self.analyze(raw)
        raw = self.fixture()
        struct.pack_into("<H", raw, 0x4ee, 0)
        with self.assertRaisesRegex(ValueError, "No eligible"):
            self.analyze(raw)

    def test_got_type_and_permissions(self):
        for raw in (self.fixture(got=True, typ=2), self.fixture(got=True, typ=22),
                    self.fixture(typ=21), self.fixture(typ=22)):
            with self.assertRaisesRegex(ValueError, "No eligible"):
                self.analyze(raw)
        raw = self.fixture(got=True)
        struct.pack_into("<I", raw, 52+32+24, 4)
        with self.assertRaisesRegex(ValueError, "No eligible"):
            self.analyze(raw)

    def test_explicit_extent_must_match_symbol(self):
        from r800_gps_interface_xref import audit
        raw = self.fixture(got=True)
        report = audit(bytes(raw), [("factory", "arm", 0x1100, 28)], symbolic=True,
                       callback_calls=True, assume_aapcs=True, callee_ranges=[("arm", 0x11c0, 4)])
        self.assertEqual(report["symbolic_callback_slot_count"], 0)
        self.assertEqual(report["code_ranges"][0]["pic_flow"]["assumed_calls"], [])

    def test_symbolic_thumb_callback(self):
        raw = self.fixture(thumb=True)
        struct.pack_into("<I", raw, 0x404, 0x302)
        report = self.analyze(raw)
        self.assertEqual(report["auto_callee_candidates"][0]["isa"], "thumb")
        call = report["code_ranges"][0]["pic_flow"]["assumed_calls"][0]
        self.assertEqual(call["target_isa"], "thumb")

    def test_versioned_symbolic_mode_still_rejected(self):
        raw = self.fixture()
        struct.pack_into("<II", raw, 0x240, 0x6ffffff0, 0x2340)
        with self.assertRaises(ValueError):
            self.analyze(raw)


if __name__ == "__main__":
    unittest.main()
