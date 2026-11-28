"""VDEX 021 location checksum comparisons, not bytecode compatibility."""
import hashlib
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zlib

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "build"))
from r800_art_inventory import jar_inventory, dex_inventory
from r800_art_vdex_binding import compare, inspect_vdex
import r800_partition_art_classpath as art
from test_r800_framework_dex import dex, jar

JAR = "/system/framework/framework.jar"
RAW = "/system/framework/extra.dex"
VDEX = "/system/framework/arm/boot.vdex"
RC = "/system/etc/init/hw/init.environ.rc"


def vdex(checksums, embedded=False):
    result = b"vdex021\0" + (b"002\0" if embedded else b"000\0")
    result += struct.pack("<4I", len(checksums), 2, 3, 4)
    result += struct.pack("<"+"I"*len(checksums), *checksums)
    if embedded:
        result += struct.pack("<3I", 8, 2, 3) + b"x"*10
    result += b"v"*2
    if embedded:
        result += b"q"*3
    return result + b"b"*3 + b"c"*4


class VdexBindingTests(unittest.TestCase):
    sha = "a"*40

    def setUp(self):
        self.a = dex(b"039")
        self.b = dex(b"035")
        self.jar = jar({"classes2.dex": self.b, "classes.dex": self.a})
        self.report, _ = jar_inventory(self.jar, 1024*1024)
        self.raw_report = {"status": "DEX_HEADER_INVENTORY_ONLY", "dex": {RAW: dex_inventory(self.a)}}
        self.artifacts = {JAR: self.report, RAW: self.raw_report}
        self.values = [zlib.crc32(self.a), zlib.crc32(self.b), struct.unpack_from("<I", self.a, 8)[0]]

    def test_ordered_zip_crc_and_raw_adler(self):
        result = compare(vdex(self.values), [JAR, RAW], self.artifacts)
        self.assertEqual(result["status"], "VDEX_ORDERED_LOCATION_CHECKSUMS_MATCH_ONLY")
        self.assertTrue(result["ordered_checksums_match"])
        self.assertEqual([r["kind"] for r in result["expected"]],
                         ["ZIP_ENTRY_CRC32", "ZIP_ENTRY_CRC32", "DEX_HEADER_ADLER32"])
        for flag in ("dex_location_identity_verified", "oat_compatibility_verified",
                     "vdex_verified", "boot_classpath_context_verified", "art_initialization_verified",
                     "safe_to_flash"):
            self.assertIs(result[flag], False)

    def test_order_mismatch(self):
        self.assertEqual(compare(vdex(self.values[::-1]), [JAR, RAW], self.artifacts)["status"],
                         "REVIEW_REQUIRED")

    def test_count_mismatch(self):
        self.assertFalse(compare(vdex(self.values[:2]), [JAR, RAW], self.artifacts)["ordered_checksums_match"])

    def test_embedded_section_bounds_only(self):
        result = inspect_vdex(vdex(self.values, True))
        self.assertEqual(result["dex_section_version"], "002")
        self.assertEqual(result["quickening_bytes"], 3)
        self.assertFalse(result["embedded_dex_verified"])

    def test_trailing_data(self):
        with self.assertRaisesRegex(ValueError, "file length"):
            inspect_vdex(vdex(self.values)+b"x")

    def test_truncated_data(self):
        with self.assertRaisesRegex(ValueError, "file length"):
            inspect_vdex(vdex(self.values, True)[:-1])

    def test_unknown_version(self):
        with self.assertRaisesRegex(ValueError, "Unsupported Android"):
            inspect_vdex(b"vdex019\0"+vdex(self.values)[8:])

    def test_missing_dex_evidence(self):
        with self.assertRaisesRegex(ValueError, "Missing DEX header evidence"):
            compare(vdex(self.values), [JAR, RAW], {JAR: self.report})

    def test_real_ext4_classpath_binding(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            tree = root/"tree"
            (tree/"etc/init/hw").mkdir(parents=True)
            (tree/"framework/arm").mkdir(parents=True)
            rc = "on early-init\n"+"".join("    export "+key+" "+JAR+":"+RAW+"\n" for key in art.CLASSPATHS)
            (tree/"etc/init/hw/init.environ.rc").write_text(rc)
            (tree/"framework/framework.jar").write_bytes(self.jar)
            (tree/"framework/extra.dex").write_bytes(self.a)
            (tree/"framework/arm/boot.vdex").write_bytes(vdex(self.values))
            image = root/"system.img"
            subprocess.run(["mke2fs", "-q", "-t", "ext4", "-F", "-d", str(tree),
                            str(image), "8192"], check=True, capture_output=True)
            specs = [["system_a", str(image), hashlib.sha256(image.read_bytes()).hexdigest(), ""]]
            with patch.object(art, "checkout_sha", return_value=self.sha):
                report = art.audit(specs, [RC], self.sha, vdex_specs=[(VDEX, JAR, RAW)])
                negative = art.audit(specs, [RC], self.sha, vdex_specs=[(VDEX, RAW, JAR)])
            self.assertEqual(report["status"], "SELECTED_LITERAL_CLASSPATH_DEX_HEADERS_ONLY")
            self.assertTrue(report["vdex_bindings"][VDEX]["ordered_checksums_match"])
            self.assertFalse(report["vdex_verified"])
            self.assertEqual(negative["status"], "REVIEW_REQUIRED")


if __name__ == "__main__":
    unittest.main()
