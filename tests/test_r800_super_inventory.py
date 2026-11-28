"""Synthetic raw LP images based on Android 11 packed metadata layouts."""
import hashlib
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "build"))
import r800_super_inventory as lp


def make_metadata(parts=None, extents=None, maximum=0, minor=2):
    parts = parts if parts is not None else [
        (b"system_a", 1, 0, 2, 0), (b"system_b", 1, 2, 0, 0)]
    extents = extents if extents is not None else [(8, 0, 32, 0), (8, 1, 0, 0)]
    rows = (parts, extents, [(b"default", 0, 0), (b"dynamic_a", 0, maximum)],
            [(32, 4096, 0, 65536, b"super", 0)])
    tables = bytearray()
    descriptors = []
    for fmt, entries in zip(lp.FORMATS, rows):
        descriptors.append((len(tables), len(entries), struct.calcsize(fmt)))
        for row in entries:
            tables.extend(struct.pack(fmt, *row))
    hs = 256 if minor == 2 else 128
    header = bytearray(hs)
    struct.pack_into("<IHHI32sI32s", header, 0, 0x414c5030, 10, minor, hs,
                     bytes(32), len(tables), hashlib.sha256(tables).digest())
    for i, desc in enumerate(descriptors):
        struct.pack_into("<III", header, 80+12*i, *desc)
    header[12:44] = lp.checksum(header, 12)
    return (header+tables).ljust(1024, b"\0")


class SuperInventoryTests(unittest.TestCase):
    sha = "a"*40

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.image = Path(tmp.name) / "super.img"
        self.raw = bytearray(65536)
        geo = bytearray(struct.pack("<II32sIII", 0x616c4467, 52, bytes(32), 1024, 2, 4096))
        geo[8:40] = lp.checksum(geo, 8)
        self.raw[4096:4096+52] = self.raw[8192:8192+52] = geo
        self.set_metadata(make_metadata())

    def set_metadata(self, raw):
        for offset in (12288, 13312, 14336, 15360):
            self.raw[offset:offset+1024] = raw

    def inspect(self, slot=0, pin=None):
        self.image.write_bytes(self.raw)
        expected = pin or hashlib.sha256(self.raw).hexdigest()
        with patch.object(lp, "checkout_sha", return_value=self.sha):
            return lp.inventory(self.image, expected, slot, self.sha)

    def test_valid_selected_slot(self):
        result = self.inspect(1)
        self.assertEqual(result["status"], "RAW_SUPER_SELECTED_SLOT_METADATA_ONLY")
        self.assertEqual(result["metadata_slot"], 1)
        system = result["partitions"]["system_a"]
        self.assertEqual(system["bytes"], 8192)
        self.assertEqual(system["extents"], [
            {"type": "linear", "offset": 16384, "bytes": 4096},
            {"type": "zero", "offset": None, "bytes": 4096}])
        self.assertEqual(result["partitions"]["system_b"]["bytes"], 0)
        for flag in ("all_slots_verified", "partition_contents_verified",
                     "avb_verified", "hardware_tested", "safe_to_flash"):
            self.assertIs(result[flag], False)

    def test_legacy_minor(self):
        self.set_metadata(make_metadata(minor=0))
        self.assertEqual(self.inspect()["version"], [10, 0])

    def test_wrong_pin(self):
        with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
            self.inspect(pin="0"*64)

    def test_sparse_refused(self):
        self.raw[:4] = b"\x3a\xff\x26\xed"
        with self.assertRaisesRegex(ValueError, "Sparse"):
            self.inspect()

    def test_geometry_checksum(self):
        self.raw[4096+8] ^= 1
        with self.assertRaisesRegex(ValueError, "geometry checksum"):
            self.inspect()

    def test_slot_outside_geometry(self):
        with self.assertRaisesRegex(ValueError, "slot outside"):
            self.inspect(2)

    def test_header_checksum(self):
        self.raw[12288+12] ^= 1
        with self.assertRaisesRegex(ValueError, "header checksum"):
            self.inspect()

    def test_tables_checksum(self):
        self.raw[12288+256] ^= 1
        with self.assertRaisesRegex(ValueError, "tables checksum"):
            self.inspect()

    def test_backup_divergence(self):
        self.raw[14336:15360] = make_metadata(extents=[(8, 0, 40, 0), (8, 1, 0, 0)])
        with self.assertRaisesRegex(ValueError, "copies disagree"):
            self.inspect()

    def test_linear_overlaps_metadata(self):
        self.set_metadata(make_metadata(extents=[(8, 0, 8, 0), (8, 1, 0, 0)]))
        with self.assertRaisesRegex(ValueError, "outside data area"):
            self.inspect()

    def test_linear_exceeds_image(self):
        self.set_metadata(make_metadata(extents=[(8, 0, 128, 0), (8, 1, 0, 0)]))
        with self.assertRaisesRegex(ValueError, "outside data area"):
            self.inspect()

    def test_physical_overlap(self):
        self.set_metadata(make_metadata(extents=[(8, 0, 32, 0), (8, 0, 32, 0)]))
        with self.assertRaisesRegex(ValueError, "Overlapping physical"):
            self.inspect()

    def test_duplicate_partition(self):
        self.set_metadata(make_metadata(parts=[(b"system_a", 1, 0, 2, 0),
                                               (b"system_a", 1, 2, 0, 0)]))
        with self.assertRaisesRegex(ValueError, "LP partition"):
            self.inspect()

    def test_group_quota(self):
        self.set_metadata(make_metadata(parts=[(b"system_a", 1, 0, 2, 1)], maximum=4096))
        with self.assertRaisesRegex(ValueError, "group size exceeded"):
            self.inspect()

    def test_zero_extent_source(self):
        self.set_metadata(make_metadata(extents=[(8, 0, 32, 0), (8, 1, 1, 0)]))
        with self.assertRaisesRegex(ValueError, "zero extent"):
            self.inspect()

    def test_shared_extent_rejected(self):
        self.set_metadata(make_metadata(parts=[(b"system_a", 1, 0, 2, 0),
                                               (b"vendor_a", 1, 0, 1, 0)]))
        with self.assertRaisesRegex(ValueError, "Shared LP extent"):
            self.inspect()


if __name__ == "__main__":
    unittest.main()
