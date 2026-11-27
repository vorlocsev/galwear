"""Offline tests for pinned KBASE ABI evidence generator."""
import sys
from pathlib import Path
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/"build"))
import r800_kbase_abi_check as mod

class KbaseAbiTests(unittest.TestCase):
    def test_import_layout(self):
        src = mod.generate()
        self.assertIn("KBASE_IOCTL_MEM_IMPORT == 0xc0188016UL", src)
        self.assertIn("offsetof(union kbase_ioctl_mem_import, in.phandle) == 8", src)
        self.assertIn("BASE_UK_VERSION_MINOR == 13", src)

    def test_wrong_blob_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            for name in mod.PINS:
                (Path(d)/name).write_bytes(b"wrong")
            with self.assertRaisesRegex(ValueError, "Unexpected pinned kernel blob"):
                mod.read_pinned(Path(d))

    def test_missing_source_evidence(self):
        with self.assertRaisesRegex(ValueError, "Pinned source evidence incomplete"):
            mod.source_evidence({name:b"" for name in mod.PINS})
