"""Synthetic acceptance tests; no QEMU or physical device required."""
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
import subprocess
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "build"))
import r800_qemu_abi_probe as a


class AbiTests(unittest.TestCase):
    def test_success(self):
        result = a.inspect_result(a.EXPECTED, b"", 0)
        self.assertEqual(result["anonymous_mapping_bytes"], 1048576)
        self.assertTrue(result["shared_memory_roundtrip"])

    def test_each_missing_stage(self):
        for line in a.EXPECTED.splitlines(keepends=True):
            with self.subTest(line=line):
                with self.assertRaisesRegex(ValueError, "Missing"):
                    a.inspect_result(a.EXPECTED.replace(line, b"", 1), b"", 0)

    def test_nonzero_exit(self):
        with self.assertRaisesRegex(ValueError, "status"):
            a.inspect_result(a.EXPECTED, b"", 1)

    def test_stderr_rejected(self):
        with self.assertRaisesRegex(ValueError, "stderr"):
            a.inspect_result(a.EXPECTED, b"r800-abi: FAIL mmap\n", 0)

    def test_reordered_stages(self):
        lines = a.EXPECTED.splitlines(keepends=True)
        lines[0], lines[1] = lines[1], lines[0]
        with self.assertRaisesRegex(ValueError, "reordered"):
            a.inspect_result(b"".join(lines), b"", 0)

    def test_duplicate_pass_rejected(self):
        with self.assertRaisesRegex(ValueError, "unexpected"):
            a.inspect_result(a.EXPECTED + b"r800-abi: PASS\n", b"", 0)

    def test_timeout_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp) / "report.json"
            with patch.object(a, "run", side_effect=subprocess.TimeoutExpired("qemu", 30)):
                with patch.object(sys, "argv", ["probe", "--probe", "unused", "--report", str(report)]):
                    self.assertEqual(a.main(), 2)
            self.assertIn('"status": "REJECT"', report.read_text())
            self.assertIn('"safe_to_flash": false', report.read_text())


if __name__ == "__main__":
    unittest.main()
