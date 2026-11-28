"""Synthetic multi-partition classpath fixtures; no Android execution."""
import hashlib
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "build"))
import r800_partition_art_classpath as art
from test_r800_framework_dex import dex, jar


RC = "/system/etc/init/hw/init.environ.rc"
DEFAULT = (
    "on early-init\n"
    "    export BOOTCLASSPATH /system/framework/framework.jar:/system_ext/framework/extra.jar\n"
    "    export DEX2OATBOOTCLASSPATH /system/framework/framework.jar\n"
    "    export SYSTEMSERVERCLASSPATH /system/framework/services.jar\n"
)


class PartitionArtClasspathTests(unittest.TestCase):
    sha = "a"*40

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)

    def image(self, name, files):
        tree = self.root/(name+"-tree")
        tree.mkdir()
        for path, raw in files.items():
            dest = tree/path
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(raw)
        image = self.root/(name+".img")
        subprocess.run(["mke2fs", "-q", "-t", "ext4", "-F", "-d", str(tree),
                        str(image), "8192"], check=True, capture_output=True)
        return [name, str(image), hashlib.sha256(image.read_bytes()).hexdigest(), ""]

    def fixture(self, rc=DEFAULT, version=b"039"):
        system = self.image("system_a", {
            "etc/init/hw/init.environ.rc": rc.encode(),
            "framework/framework.jar": jar({"classes.dex": dex(version)}),
            "framework/services.jar": jar({"classes.dex": dex()}),
        })
        extra = self.image("system_ext_a", {"framework/extra.jar": jar({"classes.dex": dex()})})
        return [system, extra]

    def audit(self, specs, rc_paths=None):
        with patch.object(art, "checkout_sha", return_value=self.sha):
            return art.audit(specs, [RC] if rc_paths is None else rc_paths, self.sha)

    def test_real_ext4_cross_partition(self):
        report = self.audit(self.fixture())
        self.assertEqual(report["status"], "SELECTED_LITERAL_CLASSPATH_DEX_HEADERS_ONLY")
        self.assertEqual(report["resolved_literal_paths"]["BOOTCLASSPATH"],
                         ["/system/framework/framework.jar", "/system_ext/framework/extra.jar"])
        self.assertEqual(len(report["artifacts"]), 3)
        self.assertEqual(report["artifacts"]["/system_ext/framework/extra.jar"]["dex"]["classes.dex"]["version"], "039")
        for flag in ("init_imports_resolved", "effective_classpath_verified", "apex_activation_verified",
                     "oat_verified", "vdex_verified", "bytecode_verified", "art_initialization_verified",
                     "hardware_tested", "safe_to_flash"):
            self.assertIs(report[flag], False)

    def test_apex_not_inferred(self):
        rc = DEFAULT.replace("/system_ext/framework/extra.jar", "/apex/com.android.art/javalib/core.jar")
        report = self.audit(self.fixture(rc))
        self.assertEqual(report["status"], "REVIEW_REQUIRED")
        self.assertEqual(report["artifacts"]["/apex/com.android.art/javalib/core.jar"]["status"],
                         "APEX_PAYLOAD_NOT_MAPPED")

    def test_missing_image_not_inferred(self):
        report = self.audit(self.fixture()[:1])
        self.assertTrue(any("No explicit partition image" in error for error in report["errors"]))

    def test_standard_dex_040(self):
        report = self.audit(self.fixture(version=b"040"))
        self.assertEqual(report["status"], "SELECTED_LITERAL_CLASSPATH_DEX_HEADERS_ONLY")
        self.assertEqual(report["artifacts"]["/system/framework/framework.jar"]["dex"]["classes.dex"]["version"], "040")

    def test_imports_remain_unexpanded(self):
        target = "/init."+"$"+"{ro.zygote}.rc"
        report = self.audit(self.fixture("import "+target+"\n"+DEFAULT))
        self.assertEqual(report["unexpanded_imports"][0]["path"], target)
        self.assertFalse(report["init_imports_resolved"])

    def test_conflicting_exports(self):
        exports, resolved, imports, errors = art.literal_exports([
            (RC, (DEFAULT+"    export BOOTCLASSPATH /system/framework/other.jar\n").encode())
        ])
        self.assertEqual(len(exports["BOOTCLASSPATH"]), 2)
        self.assertNotIn("BOOTCLASSPATH", resolved)
        self.assertTrue(errors)

    def test_dynamic_export_refused(self):
        _, resolved, _, errors = art.literal_exports([
            (RC, DEFAULT.replace("/system_ext/framework/extra.jar", "$OTHER").encode())
        ])
        self.assertNotIn("BOOTCLASSPATH", resolved)
        self.assertTrue(any("unsupported classpath" in error for error in errors))

    def test_missing_systemserver_classpath(self):
        _, resolved, _, errors = art.literal_exports([
            (RC, DEFAULT.split("    export SYSTEMSERVERCLASSPATH")[0].encode())
        ])
        self.assertNotIn("SYSTEMSERVERCLASSPATH", resolved)
        self.assertTrue(errors)

    def test_mixed_slot_rejected(self):
        with self.assertRaisesRegex(ValueError, "Mixed"):
            art.map_images([["system_a", "one", self.sha+"b"*24, ""],
                            ["system_ext_b", "two", self.sha+"b"*24, ""]])

    def test_prefix_mismatch_rejected(self):
        with self.assertRaisesRegex(ValueError, "wrong prefix"):
            art.map_images([["system_a", "one", self.sha+"b"*24, "/vendor"]])

    def test_wrong_image_pin(self):
        specs = self.fixture()
        specs[0][2] = "0"*64
        with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
            self.audit(specs)

    def test_invalid_rc_path(self):
        with self.assertRaisesRegex(ValueError, "allowed RC"):
            self.audit(self.fixture(), ["/system/../../etc/private.rc"])


if __name__ == "__main__":
    unittest.main()
