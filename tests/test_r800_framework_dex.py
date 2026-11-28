"""Exercise the shared ART parser on selected filesystem JARs."""
import hashlib
import io
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile
import zlib

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "build"))
import r800_framework_inventory as framework


def dex(version=b"039"):
    # Header and two map entries only. No executable bytecode.
    raw = bytearray(140)
    raw[:8] = b"dex\n"+version+b"\0"
    struct.pack_into("<III", raw, 32, len(raw), 112, 0x12345678)
    struct.pack_into("<I", raw, 52, 112)
    struct.pack_into("<II", raw, 104, 28, 112)
    struct.pack_into("<I", raw, 112, 2)
    struct.pack_into("<HHII", raw, 116, 0, 0, 1, 0)
    struct.pack_into("<HHII", raw, 128, 0x1000, 0, 1, 112)
    raw[12:32] = hashlib.sha1(raw[32:]).digest()
    struct.pack_into("<I", raw, 8, zlib.adler32(raw[12:]) & 0xffffffff)
    return bytes(raw)


def jar(entries):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in entries.items():
            archive.writestr(name, data)
    return stream.getvalue()


class FrameworkDexTests(unittest.TestCase):
    path = "/framework/framework.jar"
    sha = "a"*40

    def test_headers_only(self):
        data = jar({"classes.dex": dex(), "classes2.dex": dex(b"035")})
        result = framework.classify(self.path, data, True)
        self.assertEqual(result["kind"], "JAR_DEX_HEADER_INVENTORY_ONLY")
        self.assertTrue(result["dex_headers_checked"])
        self.assertFalse(result["dex_contents_verified"])
        self.assertEqual(result["dex_bytes"], 280)
        for item in result["dex_inventory"]["dex"].values():
            self.assertTrue(item["checksum_matches"])
            self.assertFalse(item["bytecode_verified"])

    def test_directory_multidex_names(self):
        data = jar({"classes.dex": dex(), "classes10.dex": dex()})
        self.assertEqual(framework.classify(self.path, data)["dex_entries"],
                         ["classes.dex", "classes10.dex"])

    def test_missing_embedded_dex_requires_review(self):
        with self.assertRaisesRegex(ValueError, "precompiled ART"):
            framework.classify(self.path, jar({"resource": b"data"}), True)

    def test_noncontiguous_multidex(self):
        with self.assertRaisesRegex(ValueError, "Noncontiguous"):
            framework.classify(self.path, jar({"classes.dex": dex(), "classes10.dex": dex()}), True)

    def test_bad_checksum(self):
        data = bytearray(dex())
        data[-1] ^= 1
        with self.assertRaisesRegex(ValueError, "SHA-1 mismatch"):
            framework.classify(self.path, jar({"classes.dex": data}), True)

    def test_unsupported_version(self):
        with self.assertRaisesRegex(ValueError, "Unsupported"):
            framework.classify(self.path, jar({"classes.dex": dex(b"041")}), True)

    def test_aggregate_budget(self):
        with self.assertRaisesRegex(ValueError, "aggregate DEX budget"):
            framework.classify(self.path, jar({"classes.dex": dex()}), True, 139)

    def test_real_ext4_strict_mode(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            tree = root/"tree"
            (tree/"framework").mkdir(parents=True)
            (tree/"framework/framework.jar").write_bytes(jar({"classes.dex": dex()}))
            (tree/"framework/services.jar").write_bytes(jar({"classes.dex": b"invalid"}))
            image = root/"system.img"
            subprocess.run(["mke2fs", "-q", "-t", "ext4", "-F", "-d", str(tree),
                            str(image), "8192"], check=True, capture_output=True)
            pin = hashlib.sha256(image.read_bytes()).hexdigest()
            with patch.object(framework, "checkout_sha", return_value=self.sha):
                report = framework.audit(image, pin, "system_a", self.sha, "",
                                         ["framework/framework.jar", "framework/services.jar"],
                                         validate_dex=True)
            self.assertTrue(report["dex_header_check_requested"])
            self.assertEqual(report["status"], "REVIEW_REQUIRED")
            self.assertTrue(report["members"][self.path]["dex_headers_checked"])
            self.assertEqual(report["members"]["/framework/services.jar"]["status"], "REVIEW_REQUIRED")
            self.assertFalse(report["dex_execution_verified"])
            self.assertFalse(report["safe_to_flash"])


if __name__ == "__main__":
    unittest.main()
