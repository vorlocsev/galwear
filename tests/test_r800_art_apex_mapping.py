"""Actual synthetic EXT4 APEX payloads, no signature or activation claims."""
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "build"))
import r800_partition_art_classpath as art
from r800_art_apex_mapping import ApexReader, mappings
from test_r800_framework_dex import dex, jar

MODULE = "com.android.art"
PACKAGE = "/system/apex/com.android.art.apex"
MEMBER = "/apex/com.android.art/javalib/core.jar"
RC = "/system/etc/init/hw/init.environ.rc"


class ArtApexMappingTests(unittest.TestCase):
    sha = "a"*40

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)

    def image(self, tree, image):
        subprocess.run(["mke2fs", "-q", "-t", "ext4", "-F", "-d", str(tree),
                        str(image), "8192"], check=True, capture_output=True)

    def package(self, outer=MODULE, inner=MODULE, inner_version=7, member=True):
        tree = self.root/"payload-tree"
        (tree/"javalib").mkdir(parents=True)
        if inner is not None:
            (tree/"apex_manifest.json").write_text(json.dumps({"name": inner, "version": inner_version}))
        if member:
            (tree/"javalib/core.jar").write_bytes(jar({"classes.dex": dex()}))
        payload = self.root/"payload.img"
        self.image(tree, payload)
        package = self.root/"module.apex"
        with zipfile.ZipFile(package, "w", compression=zipfile.ZIP_STORED) as archive:
            entry = zipfile.ZipInfo("apex_payload.img")
            pad = 4096-30-len(entry.filename)-4
            entry.extra = struct.pack("<HH", 0xCAFE, pad)+bytes(pad)
            archive.writestr(entry, payload.read_bytes())
            archive.writestr("apex_manifest.json", json.dumps({"name": outer, "version": 7}))
            archive.writestr("AndroidManifest.xml", b"synthetic")
            archive.writestr("apex_pubkey", b"synthetic-not-trusted")
        return package.read_bytes()

    def reader(self, raw, pin=None):
        return ApexReader([(MODULE, PACKAGE, pin or hashlib.sha256(raw).hexdigest())],
                          lambda path, limit: raw, self.root)

    def test_actual_payload_mapping(self):
        raw = self.package()
        reader = self.reader(raw)
        self.assertEqual(reader.read(MEMBER, 1024*1024), jar({"classes.dex": dex()}))
        reader.verify_unchanged()
        row = reader.evidence[MODULE]
        self.assertEqual(row["identity"], {"name": MODULE, "version": 7})
        self.assertFalse(row["activation_verified"])
        self.assertFalse(row["package_authenticity_verified"])

    def test_pin_mismatch(self):
        with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
            self.reader(self.package(), "0"*64).read(MEMBER, 1024*1024)

    def test_outer_identity_mismatch(self):
        with self.assertRaisesRegex(ValueError, "module mismatch"):
            self.reader(self.package(outer="com.android.runtime")).read(MEMBER, 1024*1024)

    def test_inner_identity_mismatch(self):
        with self.assertRaisesRegex(ValueError, "inner manifest mismatch"):
            self.reader(self.package(inner_version=8)).read(MEMBER, 1024*1024)

    def test_missing_inner_manifest(self):
        with self.assertRaisesRegex(ValueError, "inner manifest missing"):
            self.reader(self.package(inner=None)).read(MEMBER, 1024*1024)

    def test_missing_member(self):
        self.assertIsNone(self.reader(self.package(member=False)).read(MEMBER, 1024*1024))

    def test_duplicate_mapping(self):
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            mappings([(MODULE, PACKAGE, "a"*64), (MODULE, PACKAGE, "a"*64)])

    def test_capex_not_assumed(self):
        with self.assertRaisesRegex(ValueError, "Invalid APEX path"):
            mappings([(MODULE, PACKAGE+".capex", "a"*64)])

    def test_classpath_from_partition_package(self):
        raw = self.package()
        tree = self.root/"system-tree"
        (tree/"apex").mkdir(parents=True)
        (tree/"etc/init/hw").mkdir(parents=True)
        (tree/"apex/com.android.art.apex").write_bytes(raw)
        rc = "on early-init\n" + "".join("    export "+key+" "+MEMBER+"\n"
                                         for key in art.CLASSPATHS)
        (tree/"etc/init/hw/init.environ.rc").write_text(rc)
        image = self.root/"system.img"
        self.image(tree, image)
        with patch.object(art, "checkout_sha", return_value=self.sha):
            report = art.audit([["system_a", str(image), hashlib.sha256(image.read_bytes()).hexdigest(), ""]],
                               [RC], self.sha, apex_specs=[(MODULE, PACKAGE, hashlib.sha256(raw).hexdigest())])
        self.assertEqual(report["status"], "SELECTED_LITERAL_CLASSPATH_DEX_HEADERS_ONLY")
        self.assertEqual(report["artifacts"][MEMBER]["dex"]["classes.dex"]["version"], "039")
        self.assertIn(MODULE, report["apex_packages"])
        self.assertFalse(report["apex_activation_verified"])
        self.assertFalse(report["art_initialization_verified"])
        self.assertFalse(report["safe_to_flash"])


if __name__ == "__main__":
    unittest.main()
