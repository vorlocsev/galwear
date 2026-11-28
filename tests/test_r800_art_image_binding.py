"""Synthetic ART 085 header comparisons; no ART heap or machine code execution."""
import struct
from pathlib import Path
import sys
import unittest
import zlib

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "build"))
from r800_art_image_binding import inspect_image, compare
from r800_art_inventory import jar_inventory
from test_r800_framework_dex import dex, jar
from test_r800_art_oat_binding import make_oat
from test_r800_art_vdex_binding import vdex

JAR = "/system/framework/framework.jar"


def make_image(pointer=4, oat_checksum=0, compressed=False):
    raw = bytearray(8192)
    raw[:8] = b"art\n085\0"
    struct.pack_into("<16I", raw, 8, 16384, 1, 0x70000000, 4096,
                     123, oat_checksum, 0x70001000, 0x70002000,
                     0x70003000, 0x70004000, 0, 0, 0, 0, 0x70000200, pointer)
    struct.pack_into("<2I", raw, 72, 0, 2048)
    struct.pack_into("<2I", raw, 80, 2048, 1024)
    struct.pack_into("<2I", raw, 72+11*8, 4096, 4096)
    struct.pack_into("<3I", raw, 240, 1024 if compressed else 3840,
                     3072 if compressed else 0, 1 if compressed else 0)
    return bytes(raw)


class ArtImageTests(unittest.TestCase):
    def setUp(self):
        raw = dex()
        checksum = zlib.crc32(raw)
        self.artifacts = {JAR: jar_inventory(jar({"classes.dex": raw}), 4096)[0]}
        self.oat = make_oat([(JAR, checksum)])
        self.vdex = vdex([checksum])

    def test_arm32_triple_match(self):
        result = compare(make_image(), self.oat, self.vdex, "arm", [JAR], self.artifacts)
        self.assertEqual(result["status"], "ART_OAT_VDEX_LITERAL_HEADER_MATCH_ONLY")
        self.assertTrue(result["reported_oat_checksum_matches"])
        self.assertEqual(result["image"]["pointer_bytes"], 4)
        for key in ("boot_image_dependencies_verified", "boot_image_verified",
                    "art_initialization_verified", "hardware_tested", "safe_to_flash"):
            self.assertIs(result[key], False)

    def test_arm64_pointer(self):
        self.assertEqual(inspect_image(make_image(pointer=8), "arm64")["pointer_bytes"], 8)

    def test_pointer_mismatch(self):
        with self.assertRaisesRegex(ValueError, "pointer size"):
            inspect_image(make_image(pointer=8), "arm")

    def test_oat_checksum_mismatch(self):
        result = compare(make_image(oat_checksum=42), self.oat, self.vdex,
                         "arm", [JAR], self.artifacts)
        self.assertFalse(result["reported_oat_checksum_matches"])
        self.assertEqual(result["status"], "REVIEW_REQUIRED")

    def test_compressed_header_only(self):
        result = inspect_image(make_image(compressed=True), "arm")
        self.assertEqual(result["compressed_block_count"], 1)
        self.assertFalse(result["compressed_blocks_verified"])
        self.assertFalse(result["image_checksum_verified"])

    def test_version_mismatch(self):
        with self.assertRaisesRegex(ValueError, "ART 085"):
            inspect_image(b"art\n099\0"+make_image()[8:], "arm")

    def test_truncated_bitmap(self):
        with self.assertRaisesRegex(ValueError, "bitmap/file length"):
            inspect_image(make_image()[:-1], "arm")

    def test_overlapping_sections(self):
        raw = bytearray(make_image())
        struct.pack_into("<I", raw, 80, 1024)
        with self.assertRaisesRegex(ValueError, "Overlapping"):
            inspect_image(raw, "arm")

    def test_roots_outside(self):
        raw = bytearray(make_image())
        struct.pack_into("<I", raw, 64, 0x80000000)
        with self.assertRaisesRegex(ValueError, "roots outside"):
            inspect_image(raw, "arm")

    def test_block_table_outside(self):
        raw = bytearray(make_image(compressed=True))
        struct.pack_into("<I", raw, 244, 4090)
        with self.assertRaisesRegex(ValueError, "block table"):
            inspect_image(raw, "arm")

    def test_invalid_reservation(self):
        raw = bytearray(make_image())
        struct.pack_into("<I", raw, 8, 1)
        with self.assertRaisesRegex(ValueError, "reservation"):
            inspect_image(raw, "arm")

    def test_dependency_range(self):
        raw = bytearray(make_image())
        struct.pack_into("<4I", raw, 48, 0x71000000, 4096, 1, 123)
        with self.assertRaisesRegex(ValueError, "dependency range"):
            inspect_image(raw, "arm")


if __name__ == "__main__":
    unittest.main()
