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


def object_image(isa="arm", typ=21, other=2, section=1, size=12, value=0x2100, info=0x11):
    strings = b"\0local_table\0"
    raw = bytearray(fixture(relocs=[(0x2104, 23), (0x2108, 23), (0x1180, 23), (0x2140, 256 | typ)],
                            extra=[(4, 0x2240), (5, 0x2280), (10, len(strings)), (6, 0x22c0), (11, 16)]))
    struct.pack_into("<5I", raw, 0x440, 1, 2, 1, 0, 0)
    raw[0x480:0x480 + len(strings)] = strings
    struct.pack_into("<IIIBBH", raw, 0x4d0, 1, value, size, info, other, section)
    struct.pack_into("<I", raw, 0x180, 0x2140)
    if isa == "arm":
        struct.pack_into("<II", raw, 0x100, 0xe59f0078, 0xe5900000)
    else:
        struct.pack_into("<HH", raw, 0x100, 0x481f, 0x6800)
    return bytes(raw)


def pic_image(address, load=None, symbolic=False):
    raw = bytearray(object_image() if symbolic else image())
    delta = (address - 0x1110) & 0xffffffff
    def mov(base, imm):
        return base | ((imm & 0xf000) << 4) | (imm & 0xfff)
    struct.pack_into("<III", raw, 0x100, mov(0xe3000000, delta & 0xffff),
                     mov(0xe3400000, delta >> 16), 0xe08f0000)
    if load is not None:
        struct.pack_into("<I", raw, 0x10c, load)
    return bytes(raw)


def thumb_pic_image(address, load=None, symbolic=False, start=0x1100, reg=0):
    raw = bytearray(object_image() if symbolic else image())
    delta = (address - (start + 12)) & 0xffffffff
    def mov(base, imm):
        return (base | ((imm >> 12) & 15) | ((imm >> 1) & 0x400),
                ((imm << 4) & 0x7000) | (reg << 8) | (imm & 255))
    pos = start - 0x1000
    struct.pack_into("<5H", raw, pos, *mov(0xf240, delta & 0xffff),
                     *mov(0xf2c0, delta >> 16), 0x4478 | (reg & 7) | ((reg & 8) << 4))
    if load is not None:
        struct.pack_into("<HH", raw, pos + 10, *load)
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


    def test_symbolic_object_references(self):
        for typ in (2, 21):
            with self.subTest(typ=typ):
                raw = object_image(typ=typ)
                self.assertEqual(target.audit(raw)["symbolic_data_references"], [])
                report = target.audit(raw, symbolic=True)
                ref = report["symbolic_data_references"][0]
                self.assertEqual(ref["table_va"], 0x2100)
                self.assertEqual(ref["got_slot_candidate"], typ == 21)
                self.assertFalse(report["got_membership_verified"])

    def test_arm_thumb_got_dereference(self):
        for isa, size in (("arm", 8), ("thumb", 4)):
            with self.subTest(isa=isa):
                report = target.audit(object_image(isa=isa), [("factory", isa, 0x1100, size)], symbolic=True)
                clue = report["code_ranges"][0]["literal_load_clues"][0]
                self.assertEqual(clue["got_slot_va"], 0x2140)
                self.assertEqual(clue["table_va"], 0x2100)
                self.assertEqual(clue["reference_kind"], "ADJACENT_GOT_DEREFERENCE_CANDIDATE")
                self.assertFalse(report["safe_to_flash"])

    def test_no_dereference_on_wrong_register(self):
        raw = bytearray(object_image())
        struct.pack_into("<I", raw, 0x104, 0xe5910000)
        report = target.audit(bytes(raw), [("factory", "arm", 0x1100, 8)], symbolic=True)
        self.assertEqual(report["code_ranges"][0]["literal_load_clues"], [])

    def test_reject_ineligible_objects(self):
        for kwargs in ({"other": 0}, {"section": 0}, {"size": 8}, {"value": 0x2104}, {"typ": 22}, {"info": 0x12}):
            with self.subTest(kwargs=kwargs):
                report = target.audit(object_image(**kwargs), symbolic=True)
                self.assertEqual(report["symbolic_data_references"], [])

    def test_direct_symbolic_literal(self):
        raw = bytearray(object_image())
        struct.pack_into("<II", raw, 0x410, 0x1180, 258)
        struct.pack_into("<I", raw, 0x20c, 24)
        struct.pack_into("<I", raw, 0x180, 0)
        report = target.audit(bytes(raw), [("factory", "arm", 0x1100, 4)], symbolic=True)
        self.assertEqual(report["code_ranges"][0]["literal_load_clues"][0]["reference_kind"], "SYMBOLIC_OBJECT")

    def test_nonzero_addend_and_truncated_pair(self):
        raw = bytearray(object_image())
        struct.pack_into("<I", raw, 0x340, 4)
        self.assertEqual(target.audit(bytes(raw), symbolic=True)["symbolic_data_references"], [])
        report = target.audit(object_image(), [("factory", "arm", 0x1100, 4)], symbolic=True)
        self.assertEqual(report["code_ranges"][0]["literal_load_clues"], [])

    def test_pic_direct_table_address(self):
        raw = pic_image(0x2100)
        report = target.audit(raw, [("factory", "arm", 0x1100, 12)])
        clue = report["code_ranges"][0]["pic_clues"][0]
        self.assertEqual(clue["table_va"], 0x2100)
        self.assertEqual(clue["reference_kind"], "ARM_PIC_TABLE_ADDRESS_CANDIDATE")
        self.assertFalse(report["control_flow_verified"])

    def test_pic_symbolic_got_slot(self):
        raw = pic_image(0x2140, load=0xe5901000, symbolic=True)
        report = target.audit(raw, [("factory", "arm", 0x1100, 16)], symbolic=True)
        clue = report["code_ranges"][0]["pic_clues"][0]
        self.assertEqual((clue["slot_va"], clue["table_va"], clue["register"]), (0x2140, 0x2100, "r1"))
        self.assertEqual(clue["reference_kind"], "ARM_PIC_RELOCATED_SLOT_CANDIDATE")
        self.assertEqual(target.audit(raw, [("factory", "arm", 0x1100, 16)])["code_ranges"][0]["pic_clues"], [])

    def test_pic_signed_load_offset(self):
        for addr, op in ((0x117c, 0xe5901004), (0x1184, 0xe5101004)):
            with self.subTest(addr=addr):
                raw = pic_image(addr, load=op)
                clue = target.audit(raw, [("factory", "arm", 0x1100, 16)])["code_ranges"][0]["pic_clues"][0]
                self.assertEqual(clue["slot_va"], 0x1180)

    def test_pic_negative_delta(self):
        # Compute an address lower than the architectural PC, then load the
        # relative literal at 0x1180 using a positive immediate.
        raw = pic_image(0x1100, load=0xe5901080)
        clue = target.audit(raw, [("factory", "arm", 0x1100, 16)])["code_ranges"][0]["pic_clues"][0]
        self.assertEqual(clue["computed_va"], 0x1100)
        self.assertEqual(clue["slot_va"], 0x1180)

    def test_pic_reject_mismatched_or_conditional_ops(self):
        for offset, word in ((0x104, 0xe3401000), (0x108, 0x108f0000),
                             (0x108, 0xe08f0080), (0x108, 0xe08f0001)):
            with self.subTest(offset=offset, word=word):
                raw = bytearray(pic_image(0x2100))
                struct.pack_into("<I", raw, offset, word)
                self.assertEqual(target.audit(bytes(raw), [("factory", "arm", 0x1100, 12)])["code_ranges"][0]["pic_clues"], [])

    def test_pic_reject_relocated_instruction(self):
        raw = bytearray(pic_image(0x2100))
        struct.pack_into("<I", raw, 0x20c, 32)
        struct.pack_into("<II", raw, 0x418, 0x1104, 23)
        self.assertEqual(target.audit(bytes(raw), [("factory", "arm", 0x1100, 12)])["code_ranges"][0]["pic_clues"], [])

    def test_pic_no_partial_or_thumb_decode(self):
        raw = pic_image(0x2100)
        for isa, size in (("arm", 8), ("thumb", 12)):
            with self.subTest(isa=isa):
                self.assertEqual(target.audit(raw, [("factory", isa, 0x1100, size)])["code_ranges"][0]["pic_clues"], [])

    def test_thumb_pic_assembler_bytes(self):
        raw = thumb_pic_image(0x2100)
        self.assertEqual(raw[0x100:0x10a].hex(), "40f6f470c0f200007844")
        clue = target.audit(raw, [("factory", "thumb", 0x1100, 10)])["code_ranges"][0]["pic_clues"][0]
        self.assertEqual(clue["table_va"], 0x2100)
        self.assertEqual(clue["reference_kind"], "THUMB_PIC_TABLE_ADDRESS_CANDIDATE")

    def test_thumb_pic_got_and_high_register(self):
        raw = thumb_pic_image(0x2140, load=(0xf8d8, 0x1000), symbolic=True, reg=8)
        report = target.audit(raw, [("factory", "thumb", 0x1100, 14)], symbolic=True)
        clue = report["code_ranges"][0]["pic_clues"][0]
        self.assertEqual((clue["slot_va"], clue["table_va"], clue["register"]), (0x2140, 0x2100, "r1"))
        self.assertFalse(report["safe_to_flash"])

    def test_thumb_pic_signed_offsets(self):
        for addr, op in ((0x117c, (0xf8d0, 0x1004)), (0x1184, (0xf850, 0x1c04)),
                         (0x1100, (0xf8d0, 0x1080))):
            with self.subTest(addr=addr):
                raw = thumb_pic_image(addr, load=op)
                clue = target.audit(raw, [("factory", "thumb", 0x1100, 14)])["code_ranges"][0]["pic_clues"][0]
                self.assertEqual(clue["slot_va"], 0x1180)

    def test_thumb_pic_halfword_aligned_pc(self):
        raw = thumb_pic_image(0x2100, start=0x1102)
        clue = target.audit(raw, [("factory", "thumb", 0x1102, 10)])["code_ranges"][0]["pic_clues"][0]
        self.assertEqual(clue["computed_va"], 0x2100)

    def test_thumb_pic_reject_wrong_register_and_it(self):
        for offset, word in ((0x106, 0x0100), (0x108, 0x4479)):
            raw = bytearray(thumb_pic_image(0x2100))
            struct.pack_into("<H", raw, offset, word)
            self.assertEqual(target.audit(bytes(raw), [("factory", "thumb", 0x1100, 10)])["code_ranges"][0]["pic_clues"], [])
        raw = bytearray(thumb_pic_image(0x2100, start=0x1102))
        struct.pack_into("<H", raw, 0x100, 0xbf08)
        self.assertEqual(target.audit(bytes(raw), [("factory", "thumb", 0x1100, 12)])["code_ranges"][0]["pic_clues"], [])

    def test_thumb_pic_relocated_halfword_and_truncation(self):
        raw = bytearray(thumb_pic_image(0x2100, start=0x1102))
        struct.pack_into("<I", raw, 0x20c, 32)
        struct.pack_into("<II", raw, 0x418, 0x1100, 23)
        self.assertEqual(target.audit(bytes(raw), [("factory", "thumb", 0x1102, 10)])["code_ranges"][0]["pic_clues"], [])
        self.assertEqual(target.audit(thumb_pic_image(0x2100), [("factory", "thumb", 0x1100, 8)])["code_ranges"][0]["pic_clues"], [])

    def test_thumb_pic_wrong_load_forms(self):
        for op in ((0xf8d1, 0x1000), (0xf850, 0x1f00), (0xf8d0, 0xf000)):
            raw = thumb_pic_image(0x1180, load=op)
            self.assertEqual(target.audit(raw, [("factory", "thumb", 0x1100, 14)])["code_ranges"][0]["pic_clues"], [])


if __name__ == "__main__":
    unittest.main()
