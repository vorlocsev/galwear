"""Read-only filesystem identity with real synthetic EXT4 and EROFS headers."""
import hashlib
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "build"))
import r800_partition_identity as identity


class PartitionIdentityTests(unittest.TestCase):
    sha = "a"*40

    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.image = self.root/"system.img"

    def ext4(self, props=None, second=None):
        tree = self.root/"tree"
        tree.mkdir()
        if props is not None:
            (tree/"build.prop").write_text(props)
        if second is not None:
            (tree/"system").mkdir()
            (tree/"system"/"build.prop").write_text(second)
        subprocess.run(["mke2fs", "-q", "-t", "ext4", "-F", "-d", str(tree),
                        str(self.image), "8192"], check=True, capture_output=True)

    def inspect(self, partition="system_a", pin=None):
        pin = pin or hashlib.sha256(self.image.read_bytes()).hexdigest()
        with patch.object(identity, "checkout_sha", return_value=self.sha):
            return identity.inspect_partition(self.image, pin, partition, self.sha)

    def test_ext4_literal_identity(self):
        self.ext4("ro.build.version.sdk=30\nro.build.version.release=11\n"
                  "ro.product.cpu.abilist=armeabi-v7a,armeabi\n"
                  "ro.build.characteristics=watch\nro.serialno=private\n")
        report = self.inspect()
        self.assertEqual(report["status"], "EXT4_LITERAL_PROPERTIES_ONLY")
        self.assertEqual(report["filesystem"]["kind"], "EXT4")
        props = report["properties"]
        for flag in ("literal_android_11_hint", "literal_arm32_hint", "literal_watch_hint"):
            self.assertIs(props[flag], True)
        self.assertNotIn("ro.serialno", props["unique_values"])
        for flag in ("wear_os_runtime_verified", "donor_authenticity_verified",
                     "hardware_tested", "safe_to_flash"):
            self.assertIs(report[flag], False)

    def test_nested_system_properties(self):
        self.ext4(second="ro.build.version.sdk=30\n")
        self.assertIn("/system/build.prop", self.inspect()["property_members"])

    def test_conflict(self):
        self.ext4("ro.build.version.sdk=30\n", "ro.build.version.sdk=33\n")
        report = self.inspect()
        self.assertEqual(report["status"], "REVIEW_REQUIRED")
        self.assertIn("ro.build.version.sdk", report["properties"]["conflicts"])

    def test_missing_props(self):
        self.ext4()
        self.assertEqual(self.inspect()["status"], "REVIEW_REQUIRED")

    def test_wrong_pin(self):
        self.ext4("ro.build.version.sdk=30\n")
        with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
            self.inspect(pin="0"*64)

    def erofs(self, blocks=4, bits=12):
        raw = bytearray(16384)
        struct.pack_into("<I", raw, 1024, 0xe0f5e1e2)
        raw[1024+12] = bits
        struct.pack_into("<I", raw, 1024+36, blocks)
        self.image.write_bytes(raw)

    def test_erofs_geometry_only(self):
        self.erofs()
        report = self.inspect()
        self.assertEqual(report["status"], "REVIEW_REQUIRED")
        self.assertEqual(report["filesystem"]["kind"], "EROFS")
        self.assertEqual(report["filesystem"]["filesystem_bytes"], 16384)
        self.assertFalse(report["erofs_properties_supported"])
        self.assertFalse(report["filesystem"]["filesystem_integrity_verified"])

    def test_erofs_outside_partition(self):
        self.erofs(blocks=5)
        with self.assertRaisesRegex(ValueError, "geometry exceeds"):
            self.inspect()

    def test_erofs_bad_block_size(self):
        self.erofs(bits=31)
        with self.assertRaisesRegex(ValueError, "EROFS block size"):
            self.inspect()

    def test_unknown_filesystem(self):
        self.image.write_bytes(bytes(4096))
        with self.assertRaisesRegex(ValueError, "Unsupported partition filesystem"):
            self.inspect()

    def test_disallowed_partition(self):
        self.erofs()
        with self.assertRaisesRegex(ValueError, "allowed partition"):
            self.inspect("userdata")

    def test_conflicting_abi_not_promoted(self):
        rows = identity.literal_properties(b"ro.product.cpu.abi=armeabi-v7a\n"
                                           b"ro.product.cpu.abi=arm64-v8a\n", "/build.prop")
        self.assertFalse(identity.property_inventory(rows)["literal_arm32_hint"])

    def test_invalid_property_rejected(self):
        with self.assertRaisesRegex(ValueError, "Invalid literal property"):
            identity.literal_properties(b"ro.build.id=bad\x00value\n", "/build.prop")


if __name__ == "__main__":
    unittest.main()
