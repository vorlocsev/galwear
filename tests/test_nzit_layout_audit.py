"""Synthetic NZIT layout regression cases; no real firmware or packaging."""
from pathlib import Path
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "build"))
import r800_nzit_layout_audit as a


def image(size=4096):
    raw = bytearray(size)
    struct.pack_into("<QQQ", raw, 8, 0x80000, size, 0)
    raw[56:60] = b"ARM\x64"
    return bytes(raw)


def dtb():
    raw = bytearray(a.HISTORICAL_SLOT)
    # Empty root node plus FDT_END; this is a header fixture, not a device tree.
    struct.pack_into(">10I", raw, 0, 0xd00dfeed, len(raw), 56, 72, 40, 17, 16, 0, 0, 16)
    struct.pack_into(">4I", raw, 56, 1, 0, 2, 9)
    return bytes(raw)


def table():
    raw = bytearray(a.HISTORICAL_SLOT_OFFSET + a.HISTORICAL_SLOT)
    struct.pack_into("<3I", raw, 0, 0x4e595845, 1, 6)
    for i in range(6):
        struct.pack_into("<5I", raw, 12 + 20 * i, 9110, 0, i,
                         a.HISTORICAL_SLOT_OFFSET, a.HISTORICAL_SLOT)
    raw[a.HISTORICAL_SLOT_OFFSET:] = dtb()
    return bytes(raw)


def template():
    k, t = image(), table()
    header = struct.pack("<7I", 0x54495a4e, 32768, len(k), len(k) + 32768,
                         len(t), 0, a.HEADER)
    return header.ljust(a.HEADER, b"\0") + k + t + b"S" * a.SIGNATURE


class LayoutTests(unittest.TestCase):
    def test_historical_shared_slot(self):
        result = a.table_layout(table())
        self.assertTrue(result["historical_shared_slot_matches"])
        self.assertEqual(result["unique_slots"], 1)

    def test_duplicate_selector_rejected(self):
        raw = bytearray(table())
        raw[32:44] = raw[12:24]
        with self.assertRaisesRegex(a.LayoutError, "Duplicate"):
            a.table_layout(raw)

    def test_partial_overlap_rejected(self):
        raw = bytearray(table())
        struct.pack_into("<II", raw, 44, 2052, a.HISTORICAL_SLOT - 4)
        with self.assertRaisesRegex(a.LayoutError, "overlapping"):
            a.table_layout(raw)

    def test_out_of_bounds_rejected(self):
        raw = bytearray(table())
        struct.pack_into("<I", raw, 28, a.HISTORICAL_SLOT + 1)
        with self.assertRaisesRegex(a.LayoutError, "bounds"):
            a.table_layout(raw)

    def test_invalid_fdt_header_rejected(self):
        raw = bytearray(dtb())
        struct.pack_into(">I", raw, 4, len(raw) + 1)
        with self.assertRaisesRegex(a.LayoutError, "total size"):
            a.fdt_header(raw)

    def test_overlapping_fdt_blocks_rejected(self):
        raw = bytearray(dtb())
        struct.pack_into(">I", raw, 12, 60)
        with self.assertRaisesRegex(a.LayoutError, "overlap"):
            a.fdt_header(raw)

    def test_partition_overflow(self):
        self.assertFalse(a.budget(a.HISTORICAL_PARTITION, len(table()))["fits_historical_partition"])
        self.assertTrue(a.budget(4096, len(table()))["fits_historical_partition"])

    def test_missing_template_is_explicit_blocker(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "Image").write_bytes(image())
            (root / "tree.dtb").write_bytes(dtb())
            result = a.audit(root / "Image", root / "tree.dtb")
            self.assertIn("REFERENCE_NZIT_NOT_PROVIDED_TABLE_SIZE_ASSUMED", result["boot_blockers"])
            self.assertFalse(result["safe_to_flash"])

    def test_template_signature_never_verified(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "reference"
            path.write_bytes(template())
            result = a.inspect_template(path)
            self.assertFalse(result["signature_verified"])
            self.assertTrue(result["table"]["historical_shared_slot_matches"])

    def test_truncated_template_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "reference"
            path.write_bytes(template()[:-1])
            with self.assertRaisesRegex(a.LayoutError, "bounds"):
                a.inspect_template(path)

    def test_nonzero_partition_tail_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "reference"
            path.write_bytes(template() + b"\x01")
            with self.assertRaisesRegex(a.LayoutError, "tail"):
                a.inspect_template(path)


if __name__ == "__main__":
    unittest.main()
