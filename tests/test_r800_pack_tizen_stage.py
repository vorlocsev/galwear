"""Offline synthetic deterministic Tizen ELF archive tests."""
from pathlib import Path
import os
import sys
import tarfile
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/"build"))
from r800_stage_tizen import stage
from r800_pack_tizen_stage import pack, verify_archive, BLOCK
from test_android_linker_audit import fixture


class TizenArchiveTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.base = Path(tmp.name)
        donor = self.base / "donor"
        (donor/"usr/bin").mkdir(parents=True)
        (donor/"usr/lib").mkdir()
        (donor/"usr/bin/lhd").write_bytes(fixture("arm", needed=["libx.so"]))
        (donor/"usr/lib/libx.so").write_bytes(fixture("arm"))
        (donor/"lib").symlink_to("/usr/lib")
        self.tree = self.base/"stage"
        self.expected = stage(donor, self.tree, ["/usr/bin/lhd"])
        self.archive = self.base/"subset.tar"

    def test_reproducibility_and_exact_members(self):
        first = pack(self.tree, self.archive)
        os.utime(self.tree/"usr/lib/libx.so", (123, 123))
        second_path = self.base/"second.tar"
        second = pack(self.tree, second_path)
        self.assertEqual(self.archive.read_bytes(), second_path.read_bytes())
        self.assertEqual(first, second)
        self.assertEqual(first, verify_archive(self.archive, expected=self.expected))
        self.assertFalse(verify_archive(self.archive)["manifest_matches_expected"])
        self.assertFalse(first["safe_to_flash"])
        with tarfile.open(self.archive, "r:") as stream:
            members = stream.getmembers()
            self.assertEqual([x.name for x in members],
                             ["tizen-elf-evidence.json"] + sorted(
                                 x.lstrip("/") for x in self.expected["files"]))
            self.assertTrue(all(x.isreg() and x.uid == x.gid == x.mtime == 0
                                for x in members))

    def test_tampered_member_data(self):
        pack(self.tree, self.archive)
        with tarfile.open(self.archive, "r:") as stream:
            offset = stream.getmember("usr/lib/libx.so").offset_data
        raw = bytearray(self.archive.read_bytes())
        raw[offset + 100] ^= 1
        self.archive.write_bytes(raw)
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            verify_archive(self.archive)

    def test_tampered_member_header(self):
        pack(self.tree, self.archive)
        with tarfile.open(self.archive, "r:") as stream:
            offset = stream.getmember("usr/lib/libx.so").offset
        raw = bytearray(self.archive.read_bytes())
        raw[offset] = ord("/")
        self.archive.write_bytes(raw)
        with self.assertRaisesRegex(ValueError, "Noncanonical"):
            verify_archive(self.archive)

    def test_nonzero_padding(self):
        pack(self.tree, self.archive)
        with tarfile.open(self.archive, "r:") as stream:
            item = stream.getmembers()[0]
        self.assertNotEqual(item.size % BLOCK, 0)
        raw = bytearray(self.archive.read_bytes())
        raw[item.offset_data + item.size] = 1
        self.archive.write_bytes(raw)
        with self.assertRaisesRegex(ValueError, "padding"):
            verify_archive(self.archive)

    def test_extra_trailer_and_truncation(self):
        pack(self.tree, self.archive)
        raw = self.archive.read_bytes()
        for changed in (raw + bytes(BLOCK), raw[:-1], raw[:-1] + b"x"):
            with self.subTest(length=len(changed)):
                self.archive.write_bytes(changed)
                with self.assertRaisesRegex(ValueError, "trailer"):
                    verify_archive(self.archive)

    def test_no_overwrite_or_nested_output(self):
        self.archive.write_bytes(b"keep")
        with self.assertRaisesRegex(ValueError, "already exists"):
            pack(self.tree, self.archive)
        self.assertEqual(self.archive.read_bytes(), b"keep")
        with self.assertRaisesRegex(ValueError, "outside staging tree"):
            pack(self.tree, self.tree/"nested.tar")

    def test_changed_tree_rejected_before_publication(self):
        (self.tree/"usr/lib/extra.so").write_bytes(b"unexpected")
        with self.assertRaisesRegex(ValueError, "Unexpected file"):
            pack(self.tree, self.archive)
        self.assertFalse(self.archive.exists())

    def test_expected_manifest_mismatch(self):
        pack(self.tree, self.archive)
        changed = dict(self.expected, version_records_checked=99)
        with self.assertRaisesRegex(ValueError, "trusted staging result"):
            verify_archive(self.archive, expected=changed)


if __name__ == "__main__":
    unittest.main()
