"""Synthetic ELF dependency tests; no guest execution or device access."""
from pathlib import Path
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "build"))
import r800_android_linker_audit as audit


def fixture(abi="arm64", needed=(), bad_offset=False, unterminated=False):
    wide = abi == "arm64"
    data = bytearray(512)
    data[:7] = b"\x7fELF" + bytes([2 if wide else 1, 1, 1])
    struct.pack_into("<HH", data, 16, 3, 183 if wide else 40)
    strings = b"\0"
    offsets = []
    for name in needed:
        offsets.append(len(strings))
        strings += name.encode() + b"\0"
    data[400:400+len(strings)] = strings
    tags = [(1, 9999 if bad_offset else i) for i in offsets]
    tags += [(5, 0x1000 + 400), (10, len(strings)), (1 if unterminated else 0, 0)]
    fmt = "<qQ" if wide else "<iI"
    size = len(tags) * struct.calcsize(fmt)
    for i, pair in enumerate(tags):
        struct.pack_into(fmt, data, 224 + i * struct.calcsize(fmt), *pair)
    if wide:
        struct.pack_into("<Q", data, 32, 64)
        struct.pack_into("<HH", data, 54, 56, 2)
        struct.pack_into("<IIQQQQQQ", data, 64, 1, 5, 0, 0x1000, 0, 512, 512, 4096)
        struct.pack_into("<IIQQQQQQ", data, 120, 2, 4, 224, 0x1000+224, 0, size, size, 8)
    else:
        struct.pack_into("<I", data, 28, 52)
        struct.pack_into("<HH", data, 42, 32, 2)
        struct.pack_into("<IIIIIIII", data, 52, 1, 0, 0x1000, 0, 512, 512, 5, 4096)
        struct.pack_into("<IIIIIIII", data, 84, 2, 224, 0x1000+224, 0, size, size, 4, 4)
    return data


class LinkerTests(unittest.TestCase):
    def setUp(self):
        t = tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        self.root = Path(t.name)

    def put(self, path, data):
        f = self.root / path.lstrip("/")
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_bytes(data)

    def test_arm_and_arm64(self):
        for abi in ("arm", "arm64"):
            self.assertEqual(audit.inspect(fixture(abi, ["libc.so"]))["needed"], ["libc.so"])
            self.assertEqual(audit.inspect(fixture(abi))["abi"], abi)

    def test_bad_string_table_offset(self):
        with self.assertRaisesRegex(ValueError, "offset"):
            audit.inspect(fixture(needed=["libc.so"], bad_offset=True))

    def test_unsafe_needed(self):
        with self.assertRaisesRegex(ValueError, "Unsafe"):
            audit.inspect(fixture(needed=["../libc.so"]))

    def test_missing_dt_null(self):
        with self.assertRaisesRegex(ValueError, "DT_NULL"):
            audit.inspect(fixture(needed=["libc.so"], unterminated=True))

    def test_transitive_and_cycle(self):
        self.put("init", fixture(needed=["liba.so"]))
        self.put("system/lib64/liba.so", fixture(needed=["libb.so"]))
        self.put("system/lib64/libb.so", fixture(needed=["liba.so"]))
        out = audit.audit(self.root, ("/init",))
        self.assertEqual(out["status"], "CANDIDATES_FOUND_ONLY")
        self.assertEqual(len(out["objects"]), 3)
        self.assertFalse(out["android_namespace_resolution_verified"])
        self.assertFalse(out["safe_to_flash"])

    def test_missing_and_wrong_abi(self):
        self.put("init", fixture(needed=["libc.so"]))
        self.put("system/lib64/libc.so", fixture("arm"))
        out = audit.audit(self.root, ("/init",))
        self.assertEqual(out["status"], "REVIEW_REQUIRED")
        self.assertEqual(out["missing_candidates"][0]["needed"], "libc.so")

    def test_bionic_apex_candidate(self):
        self.put("init", fixture(needed=["libc.so"]))
        self.put("apex/com.android.runtime/lib64/bionic/libc.so", fixture())
        out = audit.audit(self.root, ("/init",))
        self.assertEqual(out["status"], "CANDIDATES_FOUND_ONLY")
        self.assertTrue(out["apex"]["com.android.runtime"]["expanded_tree_present"])
        self.assertFalse(out["apex_activation_verified"])

    def test_ambiguous_vendor_system(self):
        self.put("init", fixture(needed=["libx.so"]))
        for path in ("system/lib64/libx.so", "vendor/lib64/libx.so"):
            self.put(path, fixture())
        out = audit.audit(self.root, ("/init",))
        self.assertEqual(out["status"], "REVIEW_REQUIRED")
        self.assertEqual(len(out["ambiguous_candidates"][0]["candidates"]), 2)

    def test_symlink_alias_not_ambiguous(self):
        self.put("init", fixture(needed=["libx.so"]))
        self.put("system/lib64/libx.so", fixture())
        p = self.root / "vendor/lib64/libx.so"
        p.parent.mkdir(parents=True)
        p.symlink_to("/system/lib64/libx.so")
        self.assertEqual(audit.audit(self.root, ("/init",))["status"], "CANDIDATES_FOUND_ONLY")


if __name__ == "__main__":
    unittest.main()
