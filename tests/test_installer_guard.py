"""Synthetic, offline tests for the SM-R800 NetOdin safety gate.

No live hardware or firmware packages are used. All TAR/PIT content is invented
inside temporary directories. These tests do not establish safe bootloader use.
"""
from __future__ import annotations

import hashlib
import io
from pathlib import Path
import struct
import sys
import tarfile
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "installer"))
import netodin
import r800_safety as guard


def fake_pit(overrides=None, omit=(), corrupt_magic=False):
    entries = dict(guard.EXPECTED_IMAGES)
    entries.update(overrides or {})
    for name in omit:
        entries.pop(name, None)
    out = bytearray(28 + 132 * len(entries))
    struct.pack_into("<II", out, 0, 0 if corrupt_magic else guard.PIT_MAGIC, len(entries))
    for index, (name, partition_id) in enumerate(entries.items()):
        begin = 28 + 132 * index
        struct.pack_into("<I", out, begin + 8, partition_id)
        # Synthetic capacity: 8 MiB per partition, sequential sectors.
        # Not derived from a real Samsung PIT.
        struct.pack_into("<II", out, begin + 20, index * 16384, 16384)
        encoded = name.encode("ascii")
        out[begin + 68:begin + 68 + len(encoded)] = encoded
    return bytes(out)


def synthetic_archive(path, *, add=(), omit=(), invalid_md5=False):
    images = set(guard.EXPECTED_IMAGES) - set(omit)
    images.update(add)
    with tarfile.open(path, "w") as archive:
        for name in sorted(images):
            content = b"x"
            member = tarfile.TarInfo(name)
            member.size = len(content)
            archive.addfile(member, io.BytesIO(content))
    data = path.read_bytes()
    md5 = hashlib.md5(data).hexdigest()
    if invalid_md5:
        md5 = "0" * 32 if md5 != "0" * 32 else "f" * 32
    path.write_bytes(data + (md5 + "  R800-WearOS.tar\n").encode("ascii"))


class PITTests(unittest.TestCase):
    def test_valid_r800_layout(self):
        layout = guard.parse_pit_strict(fake_pit())
        self.assertEqual(layout, guard.EXPECTED_IMAGES)
        guard.validate_r800_pit(layout)

    def test_bad_magic_blocked(self):
        with self.assertRaises(guard.SafetyError):
            guard.parse_pit_strict(fake_pit(corrupt_magic=True))

    def test_truncated_pit_blocked(self):
        with self.assertRaises(guard.SafetyError):
            guard.parse_pit_strict(fake_pit()[:-1])

    def test_missing_layout_entry_blocked(self):
        with self.assertRaises(guard.SafetyError):
            guard.validate_r800_pit(guard.parse_pit_strict(fake_pit(omit=("dzImage",))))

    def test_changed_boot_partition_id_blocked(self):
        with self.assertRaises(guard.SafetyError):
            guard.validate_r800_pit(guard.parse_pit_strict(fake_pit(overrides={"dzImage": 99})))

    def test_duplicate_partition_id_blocked(self):
        with self.assertRaises(guard.SafetyError):
            guard.parse_pit_strict(fake_pit(overrides={"dzImage": 12}))

    def test_empty_pit_blocked(self):
        with self.assertRaises(guard.SafetyError):
            guard.parse_pit_strict(b"")


class ArchiveTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.path = Path(self.dir.name) / "R800-WearOS.tar.md5"

    def test_valid_synthetic_release(self):
        synthetic_archive(self.path)
        self.assertEqual(len(guard.preflight_file(self.path)), 12)

    def test_cm_bin_blocked(self):
        synthetic_archive(self.path, add=("cm.bin",))
        with self.assertRaises(guard.SafetyError):
            guard.preflight_file(self.path)

    def test_unknown_binary_blocked(self):
        synthetic_archive(self.path, add=("extra.img",))
        with self.assertRaises(guard.SafetyError):
            guard.preflight_file(self.path)

    def test_missing_file_blocked(self):
        synthetic_archive(self.path, omit=("sboot.bin",))
        with self.assertRaises(guard.SafetyError):
            guard.preflight_file(self.path)

    def test_corrupt_md5_blocked(self):
        synthetic_archive(self.path, invalid_md5=True)
        with self.assertRaises(guard.SafetyError):
            guard.preflight_file(self.path)

    def test_missing_trailer_blocked(self):
        with tarfile.open(self.path, "w") as a:
            m = tarfile.TarInfo("sboot.bin")
            m.size = 1
            a.addfile(m, io.BytesIO(b"a"))
        with self.assertRaises(guard.SafetyError):
            guard.preflight_file(self.path)

    def test_preflight_mode_never_opens_socket(self):
        synthetic_archive(self.path)
        with mock.patch.object(netodin.socket, "socket", side_effect=AssertionError("network accessed")):
            with mock.patch.object(sys, "argv", ["netodin.py", "--preflight-only", "--ap", str(self.path)]):
                netodin.main()

    def test_live_flash_needs_confirmation(self):
        synthetic_archive(self.path)
        with mock.patch.object(netodin.socket, "socket", side_effect=AssertionError("network accessed")):
            with mock.patch.object(sys, "argv", ["netodin.py", "--ap", str(self.path)]):
                with self.assertRaises(SystemExit) as raised:
                    netodin.main()
                self.assertEqual(raised.exception.code, 2)


class SourceChecks(unittest.TestCase):
    def test_no_default_pit_or_partition_zero(self):
        source = (ROOT / "installer" / "netodin.py").read_text(encoding="utf-8")
        self.assertNotIn("FALLBACK_PIT_MAP", source)
        self.assertNotIn("pit_map.get(filename, 0)", source)
        self.assertIn("parse_pit_strict", source)

    def test_source_compiles(self):
        import ast
        for name in ("netodin.py", "r800_safety.py"):
            ast.parse((ROOT / "installer" / name).read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
