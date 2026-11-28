"""Synthetic framework file inventories and bounded EROFS reader contracts."""
import hashlib
import io
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "build"))
import r800_framework_inventory as inventory


def jar_bytes():
    data = io.BytesIO()
    with zipfile.ZipFile(data, "w") as archive:
        archive.writestr("classes.dex", b"not executed")
        archive.writestr("classes2.dex", b"not executed")
    return data.getvalue()


class FrameworkInventoryTests(unittest.TestCase):
    sha = "a"*40

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.image = self.root/"system.img"

    def fixture(self):
        tree = self.root/"tree"
        (tree/"framework").mkdir(parents=True)
        (tree/"build.prop").write_text("ro.build.version.sdk=30\nro.build.version.release=11\n")
        (tree/"framework/framework.jar").write_bytes(jar_bytes())
        subprocess.run(["mke2fs", "-q", "-t", "ext4", "-F", "-d", str(tree),
                        str(self.image), "8192"], check=True, capture_output=True)

    def audit(self, requested, prefix="", partition="system_a"):
        with patch.object(inventory, "checkout_sha", return_value=self.sha):
            return inventory.audit(self.image, hashlib.sha256(self.image.read_bytes()).hexdigest(),
                                   partition, self.sha, prefix, requested)

    def test_real_ext4_selected_members(self):
        self.fixture()
        result = self.audit(["build.prop", "framework/framework.jar"])
        self.assertEqual(result["status"], "SELECTED_FRAMEWORK_FILES_STATIC_ONLY")
        self.assertTrue(result["properties"]["literal_android_11_hint"])
        jar = result["members"]["/framework/framework.jar"]
        self.assertEqual(jar["dex_entries"], ["classes.dex", "classes2.dex"])
        self.assertFalse(jar["dex_contents_verified"])
        for flag in ("framework_complete", "dex_execution_verified",
                     "wear_os_runtime_verified", "surfaceflinger_runtime_verified",
                     "hardware_tested", "safe_to_flash"):
            self.assertIs(result[flag], False)

    def test_missing_member_requires_review(self):
        self.fixture()
        report = self.audit(["framework/services.jar"])
        self.assertEqual(report["status"], "REVIEW_REQUIRED")
        self.assertEqual(report["members"]["/framework/services.jar"]["status"], "NOT_FOUND")

    def test_unlisted_member_rejected(self):
        self.fixture()
        with self.assertRaisesRegex(ValueError, "allowed unique"):
            self.audit(["../data/private"])

    def test_duplicate_member_rejected(self):
        self.fixture()
        with self.assertRaisesRegex(ValueError, "allowed unique"):
            self.audit(["build.prop", "build.prop"])

    def test_mismatched_root_prefix(self):
        self.fixture()
        with self.assertRaisesRegex(ValueError, "does not match"):
            self.audit(["build.prop"], "/vendor")

    def test_bad_jar_rejected(self):
        with self.assertRaises(zipfile.BadZipFile):
            inventory.classify("/framework/framework.jar", b"not a jar")

    def test_erofs_exact_size_contract(self):
        meta = b"Path : /build.prop\nSize: 3  On-disk size: 3  regular file\n"
        with patch.object(inventory, "bounded_tool", side_effect=[meta, b"abc"]) as tool:
            data = inventory.erofs_member("/trusted/dump.erofs", self.image,
                                          "/build.prop", 1024, self.root)
        self.assertEqual(data, b"abc")
        self.assertEqual(tool.call_args_list[1].args[0][1:3], ["--cat", "--path=/build.prop"])

    def test_erofs_missing_metadata_rejected(self):
        with patch.object(inventory, "bounded_tool", return_value=b""), \
             self.assertRaisesRegex(ValueError, "metadata not confirmed"):
            inventory.erofs_member("tool", self.image, "/build.prop", 1024, self.root)

    def test_erofs_nonregular_rejected(self):
        meta = b"Path : /build.prop\nSize: 3  On-disk size: 3  symlink\n"
        with patch.object(inventory, "bounded_tool", return_value=meta), \
             self.assertRaisesRegex(ValueError, "metadata not confirmed"):
            inventory.erofs_member("tool", self.image, "/build.prop", 1024, self.root)

    def test_erofs_wrong_path_rejected(self):
        meta = b"Path : /other\nSize: 3  On-disk size: 3  regular file\n"
        with patch.object(inventory, "bounded_tool", return_value=meta), \
             self.assertRaisesRegex(ValueError, "resolved path differs"):
            inventory.erofs_member("tool", self.image, "/build.prop", 1024, self.root)

    def test_erofs_truncated_output_rejected(self):
        meta = b"Path : /build.prop\nSize: 3  On-disk size: 3  regular file\n"
        with patch.object(inventory, "bounded_tool", side_effect=[meta, b"ab"]), \
             self.assertRaisesRegex(ValueError, "size mismatch"):
            inventory.erofs_member("tool", self.image, "/build.prop", 1024, self.root)

    def test_erofs_oversize_metadata_rejected(self):
        meta = b"Path : /build.prop\nSize: 1025  On-disk size: 3  regular file\n"
        with patch.object(inventory, "bounded_tool", return_value=meta), \
             self.assertRaisesRegex(ValueError, "outside budget"):
            inventory.erofs_member("tool", self.image, "/build.prop", 1024, self.root)

    def test_bounded_tool_rejects_diagnostic_with_zero_exit(self):
        with self.assertRaisesRegex(ValueError, "tool failed"):
            inventory.bounded_tool([sys.executable, "-c",
                                    "import sys; sys.stderr.write('error')"], 100, self.root)

    def test_bounded_tool_output_limit(self):
        with self.assertRaisesRegex(ValueError, "output budget"):
            inventory.bounded_tool([sys.executable, "-c", "print('x'*1000)"], 10, self.root)


if __name__ == "__main__":
    unittest.main()
