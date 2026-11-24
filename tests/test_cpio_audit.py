"""Offline synthetic newc/gzip fixtures for SM-R800 embedded /init audit."""
from __future__ import annotations

import gzip
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from contextlib import redirect_stdout

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "build"))
sys.path.insert(0, str(ROOT / "tests"))
import r800_cpio_audit as audit
from test_initramfs_recipe import fake_aarch64_elf


def make_newc(entries: list[tuple[str, int, bytes]], trailer=True):
    result = bytearray()
    for name, mode, data in entries + ([("TRAILER!!!", 0, b"")] if trailer else []):
        name_encoded = name.encode("ascii") + b"\x00"
        fields = [1, mode, 0, 0, 1, 0, len(data), 0, 0, 5 if name == "dev/console" else 0,
                  1 if name == "dev/console" else 0, len(name_encoded), 0]
        header = b"070701" + b"".join(f"{n:08x}".encode() for n in fields)
        assert len(header) == 110
        result.extend(header)
        result.extend(name_encoded)
        while len(result) % 4:
            result.append(0)
        result.extend(data)
        while len(result) % 4:
            result.append(0)
    return bytes(result)


class CpioAuditTests(unittest.TestCase):
    def setUp(self):
        t = tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        self.dir = Path(t.name)
        self.init = self.dir / "init"
        self.init.write_bytes(fake_aarch64_elf())
        self.entries = [
            ("dev", 0o040755, b""),
            ("dev/console", 0o020600, b""),
            ("proc", 0o040555, b""),
            ("sys", 0o040555, b""),
            ("data", 0o040755, b""),
            ("init", 0o100755, self.init.read_bytes()),
        ]
        self.cpio = self.dir / "payload.cpio"
        self.cpio.write_bytes(make_newc(self.entries))

    def test_six_expected_nodes_pass(self):
        result = audit.inspect_cpio(self.cpio, self.init)
        self.assertEqual(result["entries_checked"], 6)
        self.assertTrue(result["embedded_init_exact_match"])
        self.assertFalse(result["kernel_boot_tested"])
        self.assertFalse(result["safe_to_flash"])

    def test_gzip_wrapped_newc_passes(self):
        self.cpio.write_bytes(gzip.compress(make_newc(self.entries), mtime=0))
        result = audit.inspect_cpio(self.cpio, self.init)
        self.assertEqual(result["entries_checked"], 6)

    def test_wrong_embedded_init_rejected(self):
        self.entries[-1] = ("init", 0o100755, self.init.read_bytes() + b"different")
        self.cpio.write_bytes(make_newc(self.entries))
        with self.assertRaisesRegex(audit.CpioError, "differs"):
            audit.inspect_cpio(self.cpio, self.init)

    def test_wrong_init_mode_rejected(self):
        self.entries[-1] = ("init", 0o120777, self.init.read_bytes())
        self.cpio.write_bytes(make_newc(self.entries))
        with self.assertRaisesRegex(audit.CpioError, "Wrong CPIO file type"):
            audit.inspect_cpio(self.cpio, self.init)

    def test_extra_unexpected_path_rejected(self):
        self.entries.append(("../root/passwd", 0o100644, b"secret"))
        self.cpio.write_bytes(make_newc(self.entries))
        with self.assertRaisesRegex(audit.CpioError, "Unexpected CPIO entry"):
            audit.inspect_cpio(self.cpio, self.init)

    def test_duplicated_init_rejected(self):
        self.entries.append(("init", 0o100755, self.init.read_bytes()))
        self.cpio.write_bytes(make_newc(self.entries))
        with self.assertRaisesRegex(audit.CpioError, "Duplicate"):
            audit.inspect_cpio(self.cpio, self.init)

    def test_missing_init_rejected(self):
        self.cpio.write_bytes(make_newc(self.entries[:-1]))
        with self.assertRaisesRegex(audit.CpioError, "exactly six"):
            audit.inspect_cpio(self.cpio, self.init)

    def test_missing_trailer_rejected(self):
        self.cpio.write_bytes(make_newc(self.entries, trailer=False))
        with self.assertRaisesRegex(audit.CpioError, "trailer"):
            audit.inspect_cpio(self.cpio, self.init)

    def test_corrupt_magic_rejected(self):
        binary = bytearray(self.cpio.read_bytes())
        binary[:6] = b"BOGUS!"
        self.cpio.write_bytes(binary)
        with self.assertRaisesRegex(audit.CpioError, "magic"):
            audit.inspect_cpio(self.cpio, self.init)

    def test_broken_gzip_rejected_via_cli(self):
        self.cpio.write_bytes(b"\x1f\x8b" + b"not a gzip stream")
        output = self.dir / "report.json"
        with redirect_stdout(io.StringIO()):
            rc = audit.main(["--archive", str(self.cpio),
                             "--init", str(self.init),
                             "--report", str(output)])
        self.assertEqual(rc, 2)
        self.assertFalse(json.loads(output.read_text())["safe_to_flash"])

    def test_success_cli_writes_report(self):
        output = self.dir / "report.json"
        with redirect_stdout(io.StringIO()):
            rc = audit.main(["--archive", str(self.cpio),
                             "--init", str(self.init),
                             "--report", str(output)])
        self.assertEqual(rc, 0)
        self.assertEqual(json.loads(output.read_text())["entries_checked"], 6)

    def test_archive_symlink_rejected(self):
        link = self.dir / "linked.cpio"
        try:
            link.symlink_to(self.cpio)
        except (OSError, NotImplementedError):
            self.skipTest("Symlinks unavailable")
        with self.assertRaisesRegex(audit.CpioError, "symlinked"):
            audit.inspect_cpio(link, self.init)

    def test_kernel_build_uses_cpio_audit(self):
        s = (ROOT / "build/r800_kernel_compile_smoke.sh").read_text()
        self.assertIn("r800_cpio_audit.py", s)
        self.assertIn("embedded-cpio-audit.json", s)


if __name__ == "__main__":
    unittest.main()
