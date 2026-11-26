"""Mutate a real synthetic link-only ELF; never execute it."""
from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "build"))
from r800_gps_probe_linked import check

RAW = Path(sys.argv.pop(1)).read_bytes()


def ph(kind):
    start = struct.unpack_from("<I", RAW, 28)[0]
    count = struct.unpack_from("<H", RAW, 44)[0]
    return next(p for p in range(start, start+32*count, 32)
                if struct.unpack_from("<I", RAW, p)[0] == kind)


def tag(kind):
    off, _, _, size = struct.unpack_from("<4I", RAW, ph(2)+4)
    return next(p for p in range(off, off+size, 8)
                if struct.unpack_from("<I", RAW, p)[0] == kind)


def mapped(va):
    start = struct.unpack_from("<I", RAW, 28)[0]
    count = struct.unpack_from("<H", RAW, 44)[0]
    for p in range(start, start+32*count, 32):
        kind, off, addr, _, size = struct.unpack_from("<5I", RAW, p)
        if kind == 1 and addr <= va < addr+size:
            return off+va-addr
    raise AssertionError("Fixture address not mapped")


class LinkedProbeTests(unittest.TestCase):
    def reject(self, pos, value, reason):
        raw = bytearray(RAW)
        struct.pack_into("<I", raw, pos, value)
        with self.assertRaisesRegex(ValueError, reason):
            check(raw)

    def test_exact_static_contract(self):
        report = check(RAW)
        self.assertEqual(report["tls_bytes"], 4)
        self.assertEqual(report["jump_slots"], 10)
        self.assertFalse(report["safe_to_flash"])
        self.assertFalse(report["runtime_verified"])

    def test_wrong_entry(self):
        self.reject(24, 1, "entry point")
        self.reject(24, 0x10000, "mapping")

    def test_tls_geometry_and_value(self):
        self.reject(ph(7)+20, 8, "PT_TLS")
        self.reject(ph(7)+28, 8, "PT_TLS")
        self.reject(struct.unpack_from("<I", RAW, ph(7)+4)[0], 18, "initializer")

    def test_missing_tls_and_executable_stack(self):
        self.reject(ph(7), 0, "program header")
        self.reject(ph(0x6474e551)+24, 7, "Stack")

    def test_rela_and_relr_rejected(self):
        self.reject(tag(21), 7, "dynamic tag")
        self.reject(tag(21), 36, "dynamic tag")

    def test_extra_needed(self):
        self.reject(tag(21), 1, "symbol string")

    def test_jump_slot_type_and_duplicate(self):
        pos = mapped(struct.unpack_from("<I", RAW, tag(23)+4)[0])
        self.reject(pos+4, 0x102, "JUMP_SLOT")
        self.reject(pos+8, struct.unpack_from("<I", RAW, pos)[0], "JUMP_SLOT")

    def test_jump_slot_wrong_permissions(self):
        pos = mapped(struct.unpack_from("<I", RAW, tag(23)+4)[0])
        self.reject(pos, 0x10000, "mapping")


if __name__ == "__main__":
    unittest.main()
