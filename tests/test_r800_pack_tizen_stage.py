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


class ArchiveDonorBindingTests(unittest.TestCase):
    def setUp(self):
        from r800_gps_donor_snapshot import DONORS
        import hashlib
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.base = Path(tmp.name)
        self.donor = self.base / "donor"
        (self.donor / "usr/lib").mkdir(parents=True)
        (self.donor / "lib").symlink_to("/usr/lib")
        self.targets = []
        self.hashes = {}
        for name in DONORS:
            guest = "/lib/" + name
            raw = bytes(fixture("arm"))
            (self.donor / "usr/lib" / name).write_bytes(raw)
            self.targets.append(guest)
            self.hashes[name] = hashlib.sha256(raw).hexdigest()
        self.tree = self.base / "stage"
        self.expected = stage(self.donor, self.tree, self.targets)
        self.archive = self.base / "subset.tar"
        pack(self.tree, self.archive)

    def test_all_donor_aliases_bound(self):
        report = verify_archive(self.archive, donor_hashes=self.hashes)
        self.assertEqual(set(report["donor_bindings"]), set(self.hashes))
        for name, item in report["donor_bindings"].items():
            self.assertEqual(item["paths"], ["/lib/" + name, "/usr/lib/" + name])
            self.assertEqual(item["sha256"], self.hashes[name])
        self.assertFalse(report["safe_to_flash"])

    def test_wrong_or_incomplete_donor_hash_set(self):
        bad = dict(self.hashes)
        bad.pop("libdl.so.2")
        with self.assertRaisesRegex(ValueError, "donor hash set"):
            verify_archive(self.archive, donor_hashes=bad)
        bad = dict(self.hashes, **{"libc.so.6": "0"*64})
        with self.assertRaisesRegex(ValueError, "donor digest mismatch"):
            verify_archive(self.archive, donor_hashes=bad)

    def test_missing_donor_in_valid_archive(self):
        partial = self.base / "partial"
        archive = self.base / "partial.tar"
        stage(self.donor, partial, self.targets[:-1])
        pack(partial, archive)
        with self.assertRaisesRegex(ValueError, "Archive donor missing"):
            verify_archive(archive, donor_hashes=self.hashes)

    def test_publish_binds_exact_archive_and_blocks_changed_record(self):
        import hashlib
        import json
        from r800_gps_publish import publish
        binary = self.base / "binary"
        binary.write_bytes(b"synthetic bridge")
        audit = self.base / "audit.json"
        audit.write_text(json.dumps({
            "status": "STATIC_GLIBC_CLOSURE_ONLY", "static_closure_pass": True,
            "safe_to_flash": False, "runtime_verified": False, "problems": [],
            "donor_sha256": self.hashes,
            "sha256": hashlib.sha256(binary.read_bytes()).hexdigest()}))
        donor_manifest = self.base / "donors.json"
        donor_manifest.write_text(json.dumps({"sha256": self.hashes}))
        record = self.base / "archive.json"
        before = verify_archive(self.archive, donor_hashes=self.hashes)
        record.write_text(json.dumps(before))
        evidence = {}
        out = self.base / "output"
        publish(binary, audit, donor_manifest, out, evidence,
                archive=self.archive, archive_record=record)
        self.assertEqual(evidence["tizen_archive"], before)
        self.assertEqual(out.read_bytes(), binary.read_bytes())
        out.unlink()
        record.write_text(json.dumps(dict(before, sha256="0"*64)))
        with self.assertRaisesRegex(ValueError, "changed since pre-link"):
            publish(binary, audit, donor_manifest, out,
                    archive=self.archive, archive_record=record)
        self.assertFalse(out.exists())


if __name__ == "__main__":
    unittest.main()
