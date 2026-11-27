"""Fail-closed local build entrypoints; never compile a kernel or create firmware."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
BUILD = ROOT / "build"


class BuildEntrypointTests(unittest.TestCase):
    def run_script(self, name, *args):
        return subprocess.run(["sh", str(BUILD / name), *map(str, args)],
                              capture_output=True, text=True, timeout=10)

    def test_shell_syntax(self):
        for name in ("kbuild-native.sh", "mkboot.sh", "mkpayload.sh"):
            with self.subTest(name=name):
                subprocess.run(["sh", "-n", str(BUILD / name)], check=True)

    def test_legacy_invocations_rejected(self):
        for name in ("kbuild-native.sh", "mkboot.sh", "mkpayload.sh"):
            with self.subTest(name=name):
                result = self.run_script(name)
                self.assertEqual(result.returncode, 2)
                self.assertIn("usage:", result.stderr)

    def test_kernel_existing_destination_untouched(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "existing"
            out.mkdir()
            sentinel = out / "keep"
            sentinel.write_bytes(b"untouched")
            result = self.run_script("kbuild-native.sh", tmp, out)
            self.assertEqual(result.returncode, 2)
            self.assertEqual(sentinel.read_bytes(), b"untouched")

    def test_kernel_rejects_output_inside_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "new"
            result = self.run_script("kbuild-native.sh", tmp, out)
            self.assertEqual(result.returncode, 2)
            self.assertFalse(out.exists())

    def test_kernel_read_only_build_path(self):
        source = (BUILD / "kbuild-native.sh").read_text()
        self.assertIn("--no-hardlinks --no-checkout", source)
        self.assertIn("r800_initramfs_compile_smoke.sh", source)
        self.assertIn("R800_STORAGE_ISOLATION=true", source)
        self.assertIn("R800_REPRO_KHEADERS=1", source)
        self.assertIn("source-postflight.json", source)
        self.assertNotIn("/mnt/d/", source)
        self.assertNotIn("src/initramfs/build.sh", source)

    def test_packaging_delegates_to_validated_builders(self):
        boot = (BUILD / "mkboot.sh").read_text()
        payload = (BUILD / "mkpayload.sh").read_text()
        self.assertIn("r800_boot_candidate.py", boot)
        self.assertIn("copied signature does not authenticate", boot)
        self.assertIn("mkpayload-release.sh", payload)
        self.assertNotIn("rm -rf", payload)
        self.assertNotIn("~/aroot", payload)


if __name__ == "__main__":
    unittest.main()
