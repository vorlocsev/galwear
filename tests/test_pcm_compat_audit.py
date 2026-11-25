"""Source-derived PCM ABI comparison (no downloads in unit tests)."""
import importlib.util
from pathlib import Path
import unittest

path = Path(__file__).resolve().parents[1] / "build/r800_pcm_compat_audit.py"
spec = importlib.util.spec_from_file_location("pcm_compat", path)
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


class PcmCompatTests(unittest.TestCase):
    def test_matching_layout(self):
        self.assertEqual(audit.compare(dict(audit.EXPECTED)), {})

    def test_reject_bad_offsets_ioctl_and_missing_values(self):
        measured = dict(audit.EXPECTED)
        measured["sync_control_offset"] = 72
        measured["ioctl_readi"] = 0
        del measured["flag_appl"]
        self.assertEqual(set(audit.compare(measured)),
                         {"sync_control_offset", "ioctl_readi", "flag_appl"})

    def test_ioctl_numbers(self):
        self.assertEqual(audit.EXPECTED["ioctl_sync_ptr"], 0xc0844123)
        self.assertEqual(audit.EXPECTED["ioctl_readi"], 0x800c4151)
        self.assertEqual(audit.EXPECTED["ioctl_writei"], 0x400c4150)

    def test_reject_wrong_source(self):
        with self.assertRaises(ValueError):
            audit.verify_source(b"fake", b"fake")


if __name__ == "__main__":
    unittest.main()
