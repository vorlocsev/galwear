"""Synthetic executable and DEX fixtures, never executed."""
import hashlib
from pathlib import Path
import struct
import sys
import unittest
import zlib

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "build"))
from r800_stage_components import static_arm, dex


def arm_fixture():
    raw = bytearray(128)
    raw[:7] = b"\x7fELF\x01\x01\x01"
    struct.pack_into("<HH", raw, 16, 2, 40)
    struct.pack_into("<II", raw, 24, 0x10000, 52)
    struct.pack_into("<HH", raw, 42, 32, 1)
    struct.pack_into("<IIIIIIII", raw, 52, 1, 0, 0x10000, 0,
                     len(raw), len(raw), 5, 4096)
    return raw


def dex_fixture():
    raw = bytearray(112)
    raw[:8] = b"dex\n035\0"
    struct.pack_into("<III", raw, 32, len(raw), 112, 0x12345678)
    raw[12:32] = hashlib.sha1(raw[32:]).digest()
    struct.pack_into("<I", raw, 8, zlib.adler32(raw[12:]))
    return raw


class ComponentsTests(unittest.TestCase):
    def test_static_arm(self):
        static_arm(arm_fixture())

    def test_interpreter_rejected(self):
        raw = arm_fixture()
        struct.pack_into("<I", raw, 52, 3)
        with self.assertRaisesRegex(ValueError, "interpreter"):
            static_arm(raw)

    def test_wrong_machine(self):
        raw = arm_fixture()
        struct.pack_into("<H", raw, 18, 183)
        with self.assertRaisesRegex(ValueError, "headers"):
            static_arm(raw)

    def test_dex_header_integrity(self):
        dex(dex_fixture())

    def test_dex_corruption(self):
        raw = dex_fixture()
        raw[-1] = 1
        with self.assertRaisesRegex(ValueError, "signature"):
            dex(raw)


if __name__ == "__main__":
    unittest.main()
