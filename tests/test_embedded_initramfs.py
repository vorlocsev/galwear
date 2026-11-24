"""Synthetic tests for the fail-closed embedded SM-R800 initramfs Kconfig gate.

Never builds Linux, fetches kernel sources, or flashes/boots a watch.
"""
from __future__ import annotations

from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "build"))
sys.path.insert(0, str(ROOT / "tests"))
import r800_embedded_initramfs_config as gate
import r800_initramfs_spec
from test_initramfs_recipe import fake_aarch64_elf


class EmbeddedInitramfsTests(unittest.TestCase):
    def setUp(self):
        t = tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        self.dir = Path(t.name)
        self.binary = self.dir / "init"
        self.spec = self.dir / "initramfs.list"
        self.evidence = self.dir / "initramfs-evidence.json"
        self.config = self.dir / ".config"
        self.config.write_text(
            "CONFIG_ARM64=y\n" + gate.SOURCE_LINE + "\nCONFIG_SUSPEND=y\n")
        self.binary.write_bytes(fake_aarch64_elf())
        self.make_spec()

    def make_spec(self):
        data = r800_initramfs_spec.generate_spec(self.binary, self.spec)
        self.evidence.write_text(json.dumps(data))

    def test_valid_inputs_set_temporary_config_only(self):
        result = gate.prepare_config(self.config, self.spec)
        self.assertEqual(result["status"], "TEMPORARY_KCONFIG_SET_ONLY")
        self.assertIn(str(self.spec), self.config.read_text())
        self.assertTrue(result["entries"] == 6)
        self.assertFalse(result["safe_to_flash"])
        self.assertFalse(result["kernel_compiled"])
        self.assertFalse(result["boot_tested"])

    def test_input_binary_changed_after_evidence_refused(self):
        self.binary.write_bytes(fake_aarch64_elf() + b"X")
        with self.assertRaisesRegex(gate.EmbedError, "evidence"):
            gate.prepare_config(self.config, self.spec)
        self.assertIn(gate.SOURCE_LINE, self.config.read_text())

    def test_extra_cp_io_entry_refused(self):
        with self.spec.open("a") as fd:
            fd.write("file /etc/passwd /etc/passwd 0644 0 0\n")
        with self.assertRaisesRegex(gate.EmbedError, "six fixed"):
            gate.prepare_config(self.config, self.spec)

    def test_replaced_init_entry_refused(self):
        text = self.spec.read_text().replace("file /init ", "file /sbin/sh ")
        self.spec.write_text(text)
        with self.assertRaisesRegex(gate.EmbedError, "Missing regular /init"):
            gate.prepare_config(self.config, self.spec)

    def test_spec_symlink_refused(self):
        alternative = self.dir / "linked.list"
        try:
            alternative.symlink_to(self.spec)
        except (NotImplementedError, OSError):
            self.skipTest("symlinks not available")
        with self.assertRaisesRegex(gate.EmbedError, "symlinked"):
            gate.prepare_config(self.config, alternative)

    def test_binary_symlink_refused(self):
        alternative = self.dir / "other"
        try:
            alternative.symlink_to(self.binary)
        except (NotImplementedError, OSError):
            self.skipTest("symlinks not available")
        self.spec.write_text(self.spec.read_text().replace(str(self.binary), str(alternative)))
        with self.assertRaisesRegex(gate.EmbedError, "non-symlink"):
            gate.prepare_config(self.config, self.spec)

    def test_evidence_missing_refused(self):
        self.evidence.unlink()
        with self.assertRaisesRegex(gate.EmbedError, "evidence"):
            gate.prepare_config(self.config, self.spec)

    def test_evidence_authenticity_flags_missing_refused(self):
        data = json.loads(self.evidence.read_text())
        data["complete_wearos_initramfs"] = True
        self.evidence.write_text(json.dumps(data))
        with self.assertRaisesRegex(gate.EmbedError, "evidence"):
            gate.prepare_config(self.config, self.spec)

    def test_config_unexpected_path_refused(self):
        self.config.write_text('CONFIG_INITRAMFS_SOURCE="/tmp/other"\n')
        with self.assertRaisesRegex(gate.EmbedError, "unexpected"):
            gate.prepare_config(self.config, self.spec)

    def test_double_run_refused(self):
        gate.prepare_config(self.config, self.spec)
        with self.assertRaisesRegex(gate.EmbedError, "unexpected"):
            gate.prepare_config(self.config, self.spec)

    def test_cli_fail_closed_and_report_without_modifying_config(self):
        self.spec.write_text("garbage\n")
        report = self.dir / "gate.json"
        with redirect_stdout(io.StringIO()):
            rc = gate.main(["--config", str(self.config),
                            "--list", str(self.spec), "--report", str(report)])
        self.assertEqual(rc, 2)
        self.assertFalse(json.loads(report.read_text())["safe_to_flash"])
        self.assertIn(gate.SOURCE_LINE, self.config.read_text())

    def test_kernel_script_has_explicit_optin(self):
        script = (ROOT / "build/r800_kernel_compile_smoke.sh").read_text()
        self.assertIn("R800_SMOKE_INITRAMFS_LIST", script)
        self.assertIn("r800_embedded_initramfs_config.py", script)
        self.assertIn('grep -Fqx "CONFIG_INITRAMFS_SOURCE=', script)
        self.assertIn("initramfs_data.cpio", script)

    def test_original_kernel_config_unchanged(self):
        source = (ROOT / "src/kernel/r800.config").read_text()
        self.assertIn(gate.SOURCE_LINE, source)


if __name__ == "__main__":
    unittest.main()
