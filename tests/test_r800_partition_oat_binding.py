"""Read actual synthetic EXT4 OAT/VDEX pairs through the classpath auditor."""
import hashlib
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zlib

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "build"))
import r800_partition_art_classpath as art
from test_r800_framework_dex import dex, jar
from test_r800_art_oat_binding import make_oat
from test_r800_art_vdex_binding import vdex

RC = "/system/etc/init/hw/init.environ.rc"
JAR = "/system/framework/framework.jar"
OTHER = "/system/framework/services.jar"
OAT = "/system/framework/arm/boot.oat"
VDEX = "/system/framework/arm/boot.vdex"


class PartitionOatTests(unittest.TestCase):
    sha = "a"*40

    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.a, self.b = dex(b"039"), dex(b"035")
        self.sums = [zlib.crc32(self.a), zlib.crc32(self.b)]

    def fixture(self, isa="arm", locations=None, checksums=None, omit=None):
        tree = self.root/"tree"
        (tree/"etc/init/hw").mkdir(parents=True)
        (tree/"framework/arm").mkdir(parents=True)
        rc = "on early-init\n"+"".join("    export "+key+" "+JAR+":"+OTHER+"\n" for key in art.CLASSPATHS)
        files = {RC: rc.encode(), JAR: jar({"classes.dex": self.a}),
                 OTHER: jar({"classes.dex": self.b}),
                 OAT: make_oat(list(zip(locations or [JAR, OTHER], self.sums)), isa),
                 VDEX: vdex(self.sums if checksums is None else checksums)}
        for path, raw in files.items():
            if path != omit:
                (tree/path.removeprefix("/system/")).write_bytes(raw)
        image = self.root/"system.img"
        subprocess.run(["mke2fs", "-q", "-t", "ext4", "-F", "-d", str(tree),
                        str(image), "8192"], check=True, capture_output=True)
        return [["system_a", str(image), hashlib.sha256(image.read_bytes()).hexdigest(), ""]]

    def audit(self, specs, mapping=None):
        with patch.object(art, "checkout_sha", return_value=self.sha):
            return art.audit(specs, [RC], self.sha, oat_specs=[(OAT,VDEX,JAR,OTHER)] if mapping is None else mapping)

    def test_actual_ext4_pair(self):
        result = self.audit(self.fixture())
        self.assertEqual(result["status"], "SELECTED_LITERAL_CLASSPATH_DEX_HEADERS_ONLY")
        evidence = result["oat_bindings"][OAT]
        self.assertEqual(evidence["status"], "OAT_VDEX_LITERAL_LOCATION_CHECKSUMS_MATCH_ONLY")
        self.assertEqual(evidence["vdex_path"], VDEX)
        for flag in ("oat_verified", "vdex_verified", "art_initialization_verified", "safe_to_flash"):
            self.assertIs(result[flag], False)

    def test_wrong_isa(self):
        result = self.audit(self.fixture(isa="arm64"))
        self.assertIn("ELF ISA", result["oat_bindings"][OAT]["reason"])

    def test_wrong_locations_same_checksums(self):
        result = self.audit(self.fixture(locations=[OTHER,JAR]))
        self.assertFalse(result["oat_bindings"][OAT]["literal_locations_match"])
        self.assertEqual(result["status"], "REVIEW_REQUIRED")

    def test_wrong_vdex_checksums(self):
        result = self.audit(self.fixture(checksums=self.sums[::-1]))
        self.assertFalse(result["oat_bindings"][OAT]["ordered_checksums_match"])

    def test_missing_vdex(self):
        result = self.audit(self.fixture(omit=VDEX))
        self.assertIn("companion missing", result["oat_bindings"][OAT]["reason"])

    def test_different_stem(self):
        result = self.audit(self.fixture(), [(OAT,VDEX.replace("boot","other"),JAR,OTHER)])
        self.assertIn("same-stem", result["oat_bindings"][OAT]["reason"])

    def test_reordered_classpath(self):
        result = self.audit(self.fixture(), [(OAT,VDEX,OTHER,JAR)])
        self.assertIn("literal classpath order", result["oat_bindings"][OAT]["reason"])

    def test_outside_classpath(self):
        result = self.audit(self.fixture(), [(OAT,VDEX,JAR,"/system/framework/other.jar")])
        self.assertIn("outside literal classpath", result["oat_bindings"][OAT]["reason"])

    def test_duplicate_mapping(self):
        specs = self.fixture()
        with self.assertRaisesRegex(ValueError, "duplicate path"):
            self.audit(specs, [(OAT,VDEX,JAR), (OAT,VDEX,JAR)])

    def test_mapping_without_locations(self):
        specs = self.fixture()
        with self.assertRaisesRegex(ValueError, "missing locations"):
            self.audit(specs, [(OAT,VDEX)])


if __name__ == "__main__":
    unittest.main()
