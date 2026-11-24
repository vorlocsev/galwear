"""Offline-only tests for kernel source probe and compiler inventory."""
from __future__ import annotations

from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "build"))
import r800_toolchain_inventory as inventory


class ToolchainTests(unittest.TestCase):
    def test_config_versions_match_compiler_metadata(self):
        config = (ROOT / "src/kernel/r800.config").read_text()
        versions = inventory.from_config(config)
        self.assertEqual(versions["clang"], "19.1.4")
        self.assertEqual(versions["lld"], "19.1.4")

    def test_missing_config_option_rejected(self):
        with self.assertRaisesRegex(ValueError, "CONFIG_LLD_VERSION"):
            inventory.from_config("CONFIG_CLANG_VERSION=190104\n")

    def test_version_parser(self):
        self.assertEqual(inventory.parse_version("clang version 19.1.4"), "19.1.4")
        self.assertEqual(inventory.parse_version("LLD 19.1.4 (compatible)"), "19.1.4")
        self.assertIsNone(inventory.parse_version("compiler unknown"))

    @mock.patch.object(inventory.subprocess, "run")
    def test_exact_mocked_versions_report_match(self, run):
        run.return_value = mock.Mock(returncode=0, stdout="clang version 19.1.4",
                                     stderr="")
        result = inventory.inspect_toolchain(ROOT / "src/kernel/r800.config")
        self.assertTrue(result["clang_lld_versions_match_config"])
        self.assertFalse(result["reproducible_build_proven"])
        self.assertFalse(result["safe_to_flash"])

    @mock.patch.object(inventory.subprocess, "run")
    def test_mismatched_mocked_compiler_rejected(self, run):
        run.return_value = mock.Mock(returncode=0, stdout="clang version 18.1.3",
                                     stderr="")
        result = inventory.inspect_toolchain(ROOT / "src/kernel/r800.config")
        self.assertFalse(result["clang_lld_versions_match_config"])
        self.assertFalse(result["kernel_built"])

    @mock.patch.object(inventory.subprocess, "run")
    def test_unavailable_compiler_not_claimed(self, run):
        run.side_effect = FileNotFoundError("not installed")
        result = inventory.inspect_toolchain(ROOT / "src/kernel/r800.config")
        self.assertFalse(result["clang_lld_versions_match_config"])
        self.assertFalse(result["observed"]["clang"]["available"])

    @mock.patch.object(inventory.subprocess, "run")
    def test_nonzero_exit_not_marked_available(self, run):
        run.return_value = mock.Mock(returncode=1, stdout="", stderr="error")
        result = inventory.inspect_toolchain(ROOT / "src/kernel/r800.config")
        self.assertFalse(result["observed"]["clang"]["available"])

    def test_cli_report_does_not_claim_kernel_built(self):
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / "inventory.json"
            with mock.patch.object(inventory.subprocess, "run") as run:
                run.return_value = mock.Mock(returncode=0,
                    stdout="clang version 19.1.4", stderr="")
                with redirect_stdout(io.StringIO()):
                    rc = inventory.main(["--config",
                                         str(ROOT / "src/kernel/r800.config"),
                                         "--report", str(output), "--strict"])
            self.assertEqual(rc, 0)
            data = json.loads(output.read_text())
            self.assertEqual(data["status"], "VERSIONS_MATCH")
            self.assertFalse(data["kernel_built"])

    def test_strict_cli_rejects_mismatch(self):
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / "inventory.json"
            with mock.patch.object(inventory.subprocess, "run") as run:
                run.return_value = mock.Mock(returncode=0,
                    stdout="clang version 18.1.3", stderr="")
                with redirect_stdout(io.StringIO()):
                    rc = inventory.main(["--config",
                                         str(ROOT / "src/kernel/r800.config"),
                                         "--report", str(output), "--strict"])
            self.assertEqual(rc, 2)
            self.assertEqual(json.loads(output.read_text())["status"],
                             "MISMATCH_OR_UNAVAILABLE")

    def test_source_probe_has_exact_sha_and_no_write_to_remote(self):
        content = (ROOT / "build/r800_aosp_source_probe.sh").read_text()
        self.assertIn("BASE=50db73fc799f20a7120a8b5f653b16cc123d856f", content)
        self.assertIn("https://github.com/xanderlent/COMBINED_android-kernel-exynos.git", content)
        self.assertIn("git -C \"$SOURCE\" -c protocol.version=2 fetch", content)
        self.assertIn("--source-tree \"$SOURCE\"", content)
        self.assertNotIn("git push", content)
        self.assertFalse(any(line.strip().startswith("git apply ")
                             for line in content.splitlines()))
        self.assertNotIn("make -j", content)

    def test_probe_refuses_overwriting_existing_checkout(self):
        import subprocess
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            source = root / "already-exists"
            source.mkdir()
            report = root / "report.json"
            run = subprocess.run(["sh", str(ROOT / "build/r800_aosp_source_probe.sh"),
                                  str(ROOT), str(source), str(report)],
                                 capture_output=True, text=True, timeout=10)
            self.assertEqual(run.returncode, 2)
            self.assertIn("refusing overwrite", run.stderr)
            self.assertFalse(report.exists())


if __name__ == "__main__":
    unittest.main()
