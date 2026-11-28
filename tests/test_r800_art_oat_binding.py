"""Synthetic OAT 183 ELF sections and ordered location checksum evidence."""
import struct
from pathlib import Path
import sys
import unittest
import zlib

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "build"))
from r800_art_oat_binding import inspect_oat, compare
from r800_art_inventory import jar_inventory
from test_r800_framework_dex import dex, jar
from test_r800_art_vdex_binding import vdex

JAR = "/system/framework/framework.jar"


def make_oat(records, isa="arm", instruction=None, version=b"183", kv=None):
    cls, machine, default = (1, 40, 1) if isa == "arm" else (2, 183, 2)
    instruction = default if instruction is None else instruction
    kv = b"compiler-filter\0speed\0" if kv is None else kv
    data = bytearray(b"oat\n"+version+b"\0")
    data.extend(struct.pack("<13I", 0, instruction, 0, len(records), 60+len(kv),
                            4096, 0, 0, 0, 0, 0, 0, len(kv)))
    data.extend(kv)
    for location, checksum in records:
        name = location.encode("ascii")
        data.extend(struct.pack("<I", len(name))+name+struct.pack("<8I", checksum, *([0]*7)))
    strings = b"\0.rodata\0.shstrtab\0"
    image = bytearray(64)
    image[:7] = b"\x7fELF"+bytes((cls, 1, 1))
    struct.pack_into("<HH", image, 16, 3, machine)
    image.extend(data)
    image.extend(strings)
    shoff = len(image)
    if cls == 1:
        struct.pack_into("<I", image, 32, shoff)
        struct.pack_into("<6H", image, 40, 52, 0, 0, 40, 3, 2)
        fmt = "<10I"
    else:
        struct.pack_into("<Q", image, 40, shoff)
        struct.pack_into("<6H", image, 52, 64, 0, 0, 64, 3, 2)
        fmt = "<IIQQQQIIQQ"
    image.extend(struct.pack(fmt, *([0]*10)))
    image.extend(struct.pack(fmt, 1, 1, 2, 0, 64, len(data), 0, 0, 4, 0))
    image.extend(struct.pack(fmt, 9, 3, 0, 0, 64+len(data), len(strings), 0, 0, 1, 0))
    return bytes(image)


class OatBindingTests(unittest.TestCase):
    def setUp(self):
        a, b = dex(b"039"), dex(b"035")
        self.sums = [zlib.crc32(a), zlib.crc32(b)]
        self.records = list(zip([JAR, JAR+"!classes2.dex"], self.sums))
        self.artifacts = {JAR: jar_inventory(jar({"classes.dex": a, "classes2.dex": b}), 4096)[0]}

    def test_arm32_three_way_match(self):
        report = compare(make_oat(self.records), vdex(self.sums), "arm", [JAR], self.artifacts)
        self.assertEqual(report["status"], "OAT_VDEX_LITERAL_LOCATION_CHECKSUMS_MATCH_ONLY")
        self.assertTrue(report["literal_locations_match"])
        self.assertTrue(report["ordered_checksums_match"])
        self.assertEqual(report["oat"]["compiler_filter"], "speed")
        for flag in ("oat_vdex_compatibility_verified", "boot_image_verified",
                     "art_initialization_verified", "hardware_tested", "safe_to_flash"):
            self.assertIs(report[flag], False)

    def test_arm64(self):
        self.assertEqual(inspect_oat(make_oat(self.records, "arm64"), "arm64")["instruction_set"], 2)

    def test_thumb2(self):
        self.assertEqual(inspect_oat(make_oat(self.records, instruction=3), "arm")["instruction_set"], 3)

    def test_elf_isa_mismatch(self):
        with self.assertRaisesRegex(ValueError, "ELF ISA"):
            inspect_oat(make_oat(self.records, "arm64"), "arm")

    def test_header_isa_mismatch(self):
        with self.assertRaisesRegex(ValueError, "header ISA"):
            inspect_oat(make_oat(self.records, instruction=2), "arm")

    def test_location_mismatch_with_equal_checksums(self):
        altered = [("/system/framework/other.jar", self.sums[0]), self.records[1]]
        report = compare(make_oat(altered), vdex(self.sums), "arm", [JAR], self.artifacts)
        self.assertFalse(report["literal_locations_match"])
        self.assertTrue(report["ordered_checksums_match"])
        self.assertEqual(report["status"], "REVIEW_REQUIRED")

    def test_vdex_order_mismatch(self):
        report = compare(make_oat(self.records), vdex(self.sums[::-1]), "arm", [JAR], self.artifacts)
        self.assertFalse(report["ordered_checksums_match"])

    def test_unsupported_version(self):
        with self.assertRaisesRegex(ValueError, "OAT 183"):
            inspect_oat(make_oat(self.records, version=b"195"), "arm")

    def test_duplicate_location(self):
        with self.assertRaisesRegex(ValueError, "Duplicate OAT"):
            inspect_oat(make_oat([self.records[0]]*2), "arm")

    def test_duplicate_key(self):
        with self.assertRaisesRegex(ValueError, "Duplicate or empty"):
            inspect_oat(make_oat(self.records, kv=b"x\0a\0x\0b\0"), "arm")

    def test_truncated_elf(self):
        with self.assertRaisesRegex(ValueError, "section table"):
            inspect_oat(make_oat(self.records)[:-1], "arm")


if __name__ == "__main__":
    unittest.main()
