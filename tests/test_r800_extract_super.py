"""Synthetic raw/sparse super extraction; no firmware or guest execution."""
import hashlib
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch
import zlib

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "build"))
import r800_extract_super as extract
import r800_super_inventory as lp
from test_r800_super_inventory import make_metadata


def sparse(raw):
    # First four blocks carry geometry/metadata. Next block is a FILL,
    # final blocks are DONT_CARE, followed by a cumulative CRC32 chunk.
    assert raw[16384:20480] == b"ABCD"*1024 and not any(raw[20480:])
    checksum = zlib.crc32(raw)
    return (struct.pack("<I4H4I", 0xed26ff3a, 1, 0, 28, 12, 4096, 16, 4, checksum)
            + struct.pack("<HHII", 0xCAC1, 0, 4, 12+16384) + raw[:16384]
            + struct.pack("<HHII", 0xCAC2, 0, 1, 16) + b"ABCD"
            + struct.pack("<HHII", 0xCAC3, 0, 11, 12)
            + struct.pack("<HHII", 0xCAC4, 0, 0, 16) + struct.pack("<I", checksum))


class SuperExtractionTests(unittest.TestCase):
    sha = "a"*40

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.image = self.root/"super.img"
        self.out = self.root/"out"
        raw = bytearray(65536)
        geo = bytearray(struct.pack("<II32sIII", 0x616c4467, 52, bytes(32), 1024, 2, 4096))
        geo[8:40] = lp.checksum(geo, 8)
        raw[4096:4096+52] = raw[8192:8192+52] = geo
        for offset in (12288, 13312, 14336, 15360):
            raw[offset:offset+1024] = make_metadata()
        raw[16384:20480] = b"ABCD"*1024
        self.raw = bytes(raw)

    def run_extract(self, data=None, names=None, pin=None, slot=0):
        data = self.raw if data is None else data
        self.image.write_bytes(data)
        with patch.object(extract, "checkout_sha", return_value=self.sha), \
             patch.object(lp, "checkout_sha", return_value=self.sha):
            return extract.extract(self.image, pin or hashlib.sha256(data).hexdigest(),
                                   slot, ["system_a"] if names is None else names,
                                   self.out, self.sha)

    def assert_partition(self, report, fmt):
        expected = b"ABCD"*1024 + bytes(4096)
        self.assertEqual((self.out/"system_a.img").read_bytes(), expected)
        self.assertEqual(report["partitions"]["system_a"]["sha256"],
                         hashlib.sha256(expected).hexdigest())
        self.assertEqual(report["input"]["format"], fmt)
        self.assertEqual(report["input"]["raw_sha256"], hashlib.sha256(self.raw).hexdigest())
        self.assertEqual(set(p.name for p in self.out.iterdir()),
                         {"system_a.img", "super-extraction.json"})
        for flag in ("all_slots_verified", "filesystem_contents_verified",
                     "avb_verified", "wear_os_runtime_verified", "hardware_tested", "safe_to_flash"):
            self.assertIs(report[flag], False)

    def test_raw_linear_and_zero(self):
        self.assert_partition(self.run_extract(), "raw")

    def test_sparse_all_chunk_types(self):
        self.assert_partition(self.run_extract(sparse(self.raw)), "android_sparse_v1")

    def test_sparse_bad_crc_chunk(self):
        data = bytearray(sparse(self.raw))
        data[-1] ^= 1
        with self.assertRaisesRegex(ValueError, "CRC32 mismatch"):
            self.run_extract(bytes(data))
        self.assertFalse(self.out.exists())

    def test_sparse_bad_header_crc(self):
        data = bytearray(sparse(self.raw))
        data[24] ^= 1
        with self.assertRaisesRegex(ValueError, "image CRC32"):
            self.run_extract(bytes(data))

    def test_sparse_trailing_bytes(self):
        with self.assertRaisesRegex(ValueError, "Trailing"):
            self.run_extract(sparse(self.raw)+b"x")

    def test_sparse_truncated(self):
        with self.assertRaisesRegex(ValueError, "Truncated"):
            self.run_extract(sparse(self.raw)[:-1])

    def test_sparse_unknown_chunk(self):
        data = bytearray(sparse(self.raw))
        struct.pack_into("<H", data, 28, 0x1234)
        with self.assertRaisesRegex(ValueError, "Unsupported sparse chunk"):
            self.run_extract(bytes(data))

    def test_sparse_expansion_budget(self):
        data = bytearray(sparse(self.raw))
        struct.pack_into("<I", data, 16, 0xffffffff)
        with self.assertRaisesRegex(ValueError, "outside budget"):
            self.run_extract(bytes(data))

    def test_wrong_pin(self):
        with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
            self.run_extract(pin="0"*64)

    def test_inactive_partition(self):
        with self.assertRaisesRegex(ValueError, "empty or disabled"):
            self.run_extract(names=["system_b"])

    def test_nonallowlisted_partition(self):
        with self.assertRaisesRegex(ValueError, "allowed partition"):
            self.run_extract(names=["userdata"])

    def test_duplicate_partition(self):
        with self.assertRaisesRegex(ValueError, "unique allowed"):
            self.run_extract(names=["system_a", "system_a"])

    def test_existing_output(self):
        self.out.mkdir()
        with self.assertRaisesRegex(ValueError, "Fresh output"):
            self.run_extract()

    def test_slot_selection_explicit(self):
        report = self.run_extract(slot=1)
        self.assertEqual(report["metadata_slot"], 1)


if __name__ == "__main__":
    unittest.main()
