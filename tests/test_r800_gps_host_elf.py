"""Offline synthetic x86-64 ELF host dependency tests."""
import hashlib
from pathlib import Path
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/"build"))
from r800_gps_host_elf import inspect, audit, LOADER


def fixture(needed=(), *, interpreter=False, extra_tags=()):
    raw = bytearray(2048)
    raw[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HH", raw, 16, 3, 62)
    struct.pack_into("<Q", raw, 32, 64)
    struct.pack_into("<HH", raw, 54, 56, 3 if interpreter else 2)
    strings = bytearray(b"\0")
    tags = []
    for name in needed:
        tags.append((1, len(strings)))
        strings.extend(name.encode() + b"\0")
    raw[1024:1024+len(strings)] = strings
    tags.extend(((5, 0x1000+1024), (10, len(strings)), *extra_tags, (0, 0)))
    for index, tag in enumerate(tags):
        struct.pack_into("<qQ", raw, 512+16*index, *tag)
    struct.pack_into("<IIQQQQQQ", raw, 64, 1, 5, 0, 0x1000, 0,
                     len(raw), len(raw), 4096)
    size = 16*len(tags)
    struct.pack_into("<IIQQQQQQ", raw, 120, 2, 4, 512, 0x1200, 0, size, size, 8)
    if interpreter:
        value = LOADER.encode()+b"\0"
        raw[768:768+len(value)] = value
        struct.pack_into("<IIQQQQQQ", raw, 176, 3, 4, 768, 0x1300, 0,
                         len(value), len(value), 1)
    return raw


class HostElfTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.lib = self.root/"lib"
        self.lib.mkdir()
        self.tool = self.root/"clang"
        self.loader = self.lib/"loader"
        self.tool.write_bytes(fixture(["liba.so"], interpreter=True))
        self.loader.write_bytes(fixture())
        (self.lib/"liba.so").write_bytes(fixture(["libb.so"]))
        (self.lib/"libb.so").write_bytes(fixture())

    def report(self, *dirs):
        return audit({"clang": self.tool}, directories=dirs or (self.lib,), loader=self.loader)

    def test_transitive_closure_and_loader(self):
        report = self.report()
        self.assertEqual(report["status"], "HOST_STATIC_CANDIDATES_ONLY")
        self.assertEqual(len(report["objects"]), 4)
        self.assertEqual(report["bindings"][LOADER], str(self.loader))
        provider = self.lib/"libb.so"
        self.assertEqual(report["objects"][str(provider)]["sha256"],
                         hashlib.sha256(provider.read_bytes()).hexdigest())
        self.assertFalse(report["loader_search_verified"])
        self.assertFalse(report["host_isolated"])

    def test_missing_and_ambiguous_providers(self):
        (self.lib/"libb.so").unlink()
        report = self.report()
        self.assertEqual(report["problems"][0]["reason"], "MISSING")
        (self.lib/"libb.so").write_bytes(fixture())
        other = self.root/"other"
        other.mkdir()
        (other/"libb.so").write_bytes(fixture())
        self.assertEqual(self.report(self.lib, other)["problems"][0]["reason"], "AMBIGUOUS")

    def test_same_canonical_alias_not_ambiguous(self):
        alias = self.root/"alias"
        alias.symlink_to(self.lib, target_is_directory=True)
        self.assertEqual(self.report(self.lib, alias)["problems"], [])

    def test_changed_dependency_changes_evidence(self):
        before = self.report()
        provider = self.lib/"libb.so"
        raw = bytearray(provider.read_bytes())
        raw[-1] ^= 1
        provider.write_bytes(raw)
        self.assertNotEqual(before, self.report())

    def test_custom_path_and_unsafe_names(self):
        for tag in (15, 29, 0x6ffffefb, 0x7fffffff):
            with self.subTest(tag=tag), self.assertRaisesRegex(ValueError, "custom search"):
                inspect(fixture(extra_tags=((tag, 0),)))
        for name in ("../libx.so", "/lib/x.so", ".."):
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "Unsafe"):
                inspect(fixture([name]))

    def test_malformed_headers(self):
        raw = fixture()
        struct.pack_into("<H", raw, 18, 183)
        with self.assertRaisesRegex(ValueError, "x86-64"):
            inspect(raw)
        raw = fixture(["libx.so"])
        struct.pack_into("<Q", raw, 120+16, 0x1300)
        with self.assertRaisesRegex(ValueError, "dynamic table"):
            inspect(raw)


if __name__ == "__main__":
    unittest.main()
