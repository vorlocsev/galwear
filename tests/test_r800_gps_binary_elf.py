"""Binary ELF fixtures for the GPS glibc gate; no ELF is executed."""
import struct
import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "build"))
import r800_android_linker_audit as parser
from r800_gps_link_gate import elf
from test_android_linker_audit import symbol_fixture, relocation_fixture


def arm_fixture(executable=False):
    data = symbol_fixture("arm")
    struct.pack_into("<I", data, 36, 0x05000200)
    if executable:
        struct.pack_into("<H", data, 16, 2)
        struct.pack_into("<H", data, 44, 3)
        interp = b"/lib/ld-linux.so.3\0"
        data[480:480 + len(interp)] = interp
        struct.pack_into("<8I", data, 116, 3, 480, 0x1000 + 480, 0,
                         len(interp), len(interp), 4, 1)
    return data


def append_tags(data, tags):
    size, = struct.unpack_from("<I", data, 100)
    offset = 224 + size - 8
    for tag, value in [*tags, (0, 0)]:
        struct.pack_into("<iI", data, offset, tag, value)
        offset += 8
    size = offset - 224
    struct.pack_into("<II", data, 100, size, size)


def packed_fixture(kind, executable=False):
    data = arm_fixture(executable)
    struct.pack_into("<I", data, 76, 6)
    if kind in ("APS2_REL", "APS2_RELA"):
        # Empty but valid APS2 table: header, count=0, initial offset=0.
        blob = b"APS2\0\0"
        a, s = ((parser.DT_ANDROID_REL, parser.DT_ANDROID_RELSZ)
                if kind == "APS2_REL" else
                (parser.DT_ANDROID_RELA, parser.DT_ANDROID_RELASZ))
        tags = [(a, 0x1000 + 940), (s, len(blob))]
    else:
        blob = struct.pack("<I", 0x1000 + 1000)
        a, s, e = ((parser.DT_RELR, parser.DT_RELRSZ, parser.DT_RELRENT)
                   if kind == "RELR" else
                   (parser.DT_ANDROID_RELR, parser.DT_ANDROID_RELRSZ,
                    parser.DT_ANDROID_RELRENT))
        tags = [(a, 0x1000 + 940), (s, len(blob)), (e, 4)]
    data[940:940 + len(blob)] = blob
    append_tags(data, tags)
    return data


class GpsBinaryElfTests(unittest.TestCase):
    def test_valid_dso(self):
        self.assertEqual(elf(arm_fixture())["elf_type"], "ET_DYN")

    def test_valid_executable(self):
        self.assertEqual(elf(arm_fixture(True), executable=True)["elf_type"], "ET_EXEC")

    def test_normal_rel_accepted(self):
        data = relocation_fixture("arm")
        struct.pack_into("<I", data, 36, 0x05000200)
        self.assertEqual(elf(data)["relocations"]["tables"][0]["count"], 1)

    def test_packed_rejected_after_real_parser_acceptance(self):
        for kind in ("APS2_REL", "APS2_RELA", "RELR", "ANDROID_RELR"):
            for executable in (False, True):
                with self.subTest(kind=kind, executable=executable):
                    data = packed_fixture(kind, executable)
                    self.assertTrue(parser.inspect(data)["relocations"]["tables"])
                    with self.assertRaisesRegex(ValueError, "Unsupported.*(APS2|RELR|packed)|Relocations require review"):
                        elf(data, executable=executable)

    def test_hard_float(self):
        data = arm_fixture()
        struct.pack_into("<I", data, 36, 0x05000400)
        with self.assertRaisesRegex(ValueError, "EABI5"):
            elf(data)

    def test_wrong_eabi(self):
        data = arm_fixture()
        struct.pack_into("<I", data, 36, 0x04000200)
        with self.assertRaisesRegex(ValueError, "EABI5"):
            elf(data)

    def test_arm64(self):
        with self.assertRaisesRegex(ValueError, "Expected ARM32"):
            elf(symbol_fixture("arm64"))

    def test_truncated_header(self):
        with self.assertRaises(ValueError):
            elf(arm_fixture()[:40])

    def test_bad_program_header_count(self):
        data = arm_fixture()
        struct.pack_into("<H", data, 44, 129)
        with self.assertRaisesRegex(ValueError, "program header"):
            elf(data)

    def test_missing_interpreter(self):
        data = arm_fixture()
        struct.pack_into("<H", data, 16, 2)
        with self.assertRaisesRegex(ValueError, "PT_INTERP"):
            elf(data, executable=True)

    def test_malformed_packed_table(self):
        data = packed_fixture("APS2_REL")
        data[940:944] = b"BAD!"
        with self.assertRaisesRegex(ValueError, "APS2 signature"):
            elf(data)


if __name__ == "__main__":
    unittest.main()
