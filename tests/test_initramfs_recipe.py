"""Synthetic AArch64 initramfs recipe tests; no actual compiler or watch."""
from __future__ import annotations

from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "build"))
import r800_initramfs_spec as spec


def fake_aarch64_elf(*, machine=183, interpreter=False,
                     bad_segment=False, bad_phdr=False) -> bytes:
    binary = bytearray(256)
    binary[:4] = b"\x7fELF"
    binary[4:7] = b"\x02\x01\x01"
    struct.pack_into("<HHI", binary, 16, 2, machine, 1)
    struct.pack_into("<Q", binary, 24, 0x400100)
    struct.pack_into("<Q", binary, 32, 64)
    struct.pack_into("<HH", binary, 54, 56, 2 if interpreter else 1)
    struct.pack_into("<II", binary, 64, 1, 5)  # PT_LOAD, PF_R | PF_X
    struct.pack_into("<QQ", binary, 64 + 8, 192, 0x400100)
    struct.pack_into("<QQ", binary, 64 + 32, 128 if bad_segment else 32, 32)
    if interpreter:
        struct.pack_into("<I", binary, 120, 3)
    if bad_phdr:
        struct.pack_into("<Q", binary, 32, 250)
    return bytes(binary)


class InitramfsRecipeTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.folder = Path(tmp.name)
        self.init = self.folder / "init"
        self.init.write_bytes(fake_aarch64_elf())

    def test_minimal_static_aarch64_elf_accepted(self):
        result = spec.validate_init(self.init)
        self.assertEqual(result["machine"], "AArch64")
        self.assertTrue(result["static_no_interp"])
        self.assertEqual(result["size_bytes"], 256)
        self.assertEqual(len(result["sha256"]), 64)

    def test_x86_binary_rejected(self):
        self.init.write_bytes(fake_aarch64_elf(machine=62))
        with self.assertRaisesRegex(spec.InitramfsError, "AArch64"):
            spec.validate_init(self.init)

    def test_invalid_magic_rejected(self):
        self.init.write_bytes(b"MZ" + b"x" * 254)
        with self.assertRaisesRegex(spec.InitramfsError, "ELF64"):
            spec.validate_init(self.init)

    def test_dynamic_interpreter_rejected(self):
        self.init.write_bytes(fake_aarch64_elf(interpreter=True))
        with self.assertRaisesRegex(spec.InitramfsError, "interpreter"):
            spec.validate_init(self.init)

    def test_bad_program_header_bounds_rejected(self):
        self.init.write_bytes(fake_aarch64_elf(bad_phdr=True))
        with self.assertRaisesRegex(spec.InitramfsError, "headers exceed"):
            spec.validate_init(self.init)

    def test_bad_load_segment_bounds_rejected(self):
        self.init.write_bytes(fake_aarch64_elf(bad_segment=True))
        with self.assertRaisesRegex(spec.InitramfsError, "LOAD segment"):
            spec.validate_init(self.init)

    def test_entry_must_be_file_backed_and_executable(self):
        cases = (
            ("outside LOAD", 24, "<Q", 0x500000),
            ("non-executable LOAD", 68, "<I", 4),
            ("misaligned entry", 24, "<Q", 0x400101),
            ("partial instruction", 96, "<Q", 2),
            ("entry in zero-fill tail", 96, "<Q", 0),
        )
        for label, offset, fmt, value in cases:
            with self.subTest(label=label):
                data = bytearray(fake_aarch64_elf())
                struct.pack_into(fmt, data, offset, value)
                self.init.write_bytes(data)
                with self.assertRaisesRegex(spec.InitramfsError, "entry must"):
                    spec.validate_init(self.init)

    def test_load_file_size_cannot_exceed_memory_size(self):
        data = bytearray(fake_aarch64_elf())
        struct.pack_into("<Q", data, 104, 16)
        self.init.write_bytes(data)
        with self.assertRaisesRegex(spec.InitramfsError, "memory size"):
            spec.validate_init(self.init)

    def test_load_virtual_address_overflow_rejected(self):
        data = bytearray(fake_aarch64_elf())
        struct.pack_into("<Q", data, 80, (1 << 64) - 16)
        self.init.write_bytes(data)
        with self.assertRaisesRegex(spec.InitramfsError, "memory size"):
            spec.validate_init(self.init)

    def test_symlink_input_refused(self):
        link = self.folder / "link-init"
        try:
            link.symlink_to(self.init)
        except (NotImplementedError, OSError):
            self.skipTest("No symlink support")
        with self.assertRaisesRegex(spec.InitramfsError, "symlinked"):
            spec.validate_init(link)

    def test_symlink_cannot_be_used_for_spec_generation(self):
        link = self.folder / "linked-init"
        try:
            link.symlink_to(self.init)
        except (NotImplementedError, OSError):
            self.skipTest("No symlink support")
        output = self.folder / "initramfs.list"
        with self.assertRaisesRegex(spec.InitramfsError, "symlinked"):
            spec.generate_spec(link, output)
        self.assertFalse(output.exists())

    def test_generates_deterministic_entries(self):
        first = self.folder / "first.list"
        second = self.folder / "second.list"
        report1 = spec.generate_spec(self.init, first)
        report2 = spec.generate_spec(self.init, second)
        self.assertEqual(first.read_bytes(), second.read_bytes())
        self.assertEqual(report1, report2)
        self.assertIn(f"file /init {self.init.resolve()} 0755 0 0", first.read_text())
        self.assertIn("nod /dev/console 0600 0 0 c 5 1", first.read_text())
        self.assertFalse(report1["complete_wearos_initramfs"])
        self.assertFalse(report1["image_flashed"])

    def test_cli_writes_minimal_report(self):
        out = self.folder / "initramfs.list"
        evidence = self.folder / "evidence.json"
        with redirect_stdout(io.StringIO()):
            rc = spec.main(["--init", str(self.init),
                            "--list", str(out), "--report", str(evidence)])
        self.assertEqual(rc, 0)
        data = json.loads(evidence.read_text())
        self.assertEqual(data["status"], "NON_RELEASE_INITRAMFS_SPEC_ONLY")
        self.assertTrue(out.is_file())

    def test_cli_refuses_bad_elf(self):
        self.init.write_text("invalid executable")
        out = self.folder / "initramfs.list"
        evidence = self.folder / "rejected.json"
        with redirect_stdout(io.StringIO()):
            rc = spec.main(["--init", str(self.init),
                            "--list", str(out), "--report", str(evidence)])
        self.assertEqual(rc, 2)
        self.assertEqual(json.loads(evidence.read_text())["status"], "REJECT")
        self.assertFalse(out.exists())

    def test_compile_script_shell_syntax_and_toolchain_pin(self):
        script = ROOT / "build/r800_initramfs_compile_smoke.sh"
        p = subprocess.run(["sh", "-n", str(script)], capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stderr)
        s = script.read_text()
        self.assertIn("clang-19 --version", s)
        self.assertIn("19\\.1\\.4", s)
        self.assertIn("-ffreestanding -nostdlib -static", s)
        self.assertIn("-Wl,--build-id=none", s)

    def test_compile_script_rejects_missing_arguments(self):
        script = ROOT / "build/r800_initramfs_compile_smoke.sh"
        p = subprocess.run(["sh", str(script)], capture_output=True, text=True)
        self.assertEqual(p.returncode, 2)
        self.assertIn("usage:", p.stderr)

    def test_workflow_cannot_upload_executable_or_release(self):
        content = (ROOT / ".github/workflows/r800-initramfs-smoke.yml").read_text()
        self.assertIn("r800-initramfs-evidence", content)
        self.assertNotIn("gh release", content)
        self.assertNotIn("images/R800-WearOS.tar.md5", content)


if __name__ == "__main__":
    unittest.main()
