"""Synthetic section and block hash diagnostics; no kernel build required."""
import hashlib
from pathlib import Path
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "build"))
import r800_kernel_diff_evidence as diag


def elf(payload):
    data = bytearray(512)
    data[:6] = b"\x7fELF\x02\x01"
    struct.pack_into("<H", data, 18, 183)
    struct.pack_into("<Q", data, 40, 64)
    struct.pack_into("<HHH", data, 58, 64, 3, 1)
    names = b"\0.shstrtab\0.text\0"
    struct.pack_into("<IIQQQQIIQQ", data, 128, 1, 3, 0, 0, 256, len(names), 0, 0, 1, 0)
    struct.pack_into("<IIQQQQIIQQ", data, 192, 11, 1, 2, 4096, 320, len(payload), 0, 0, 1, 0)
    data[256:256+len(names)] = names
    data[320:320+len(payload)] = payload
    return bytes(data)


class KernelDiffEvidenceTests(unittest.TestCase):
    def test_section_content_only(self):
        a = diag.sections(elf(b"abc"))
        b = diag.sections(elf(b"abd"))
        self.assertEqual(list(a), [".text"])
        self.assertEqual(a[".text"]["address"], 4096)
        self.assertEqual(a[".text"]["sha256"], hashlib.sha256(b"abc").hexdigest())
        self.assertNotEqual(a[".text"], b[".text"])

    def test_wrong_elf_rejected(self):
        with self.assertRaises(ValueError):
            diag.sections(b"not ELF")

    def test_image_block_localization(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            image = root / "arch/arm64/boot/Image"
            image.parent.mkdir(parents=True)
            data = bytearray(diag.BLOCK + 10)
            data[56:60] = b"ARM\x64"
            image.write_bytes(data)
            (root / "vmlinux").write_bytes(elf(b"abc"))
            a = diag.snapshot(root)
            data[-1] = 1
            image.write_bytes(data)
            b = diag.snapshot(root)
            self.assertEqual(a["blocks"][0], b["blocks"][0])
            self.assertNotEqual(a["blocks"][1], b["blocks"][1])
            self.assertNotEqual(a["image_sha256"], b["image_sha256"])
            self.assertEqual(a["sections"], b["sections"])
            self.assertFalse(a["safe_to_flash"])


if __name__ == "__main__":
    unittest.main()
