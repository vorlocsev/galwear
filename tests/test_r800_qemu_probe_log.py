import sys
from pathlib import Path
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "build"))
from r800_qemu_probe_log import MARKERS, valid_log

class ProbeLogTests(unittest.TestCase):
    def setUp(self):
        self.lines = [key + "=PASS" for key in MARKERS]

    def test_success(self):
        self.assertTrue(valid_log("diagnostic\n" + "\n".join(self.lines)))

    def test_missing(self):
        self.assertFalse(valid_log("\n".join(self.lines[:-1])))

    def test_duplicate(self):
        self.assertFalse(valid_log("\n".join(self.lines + self.lines[:1])))

    def test_contradiction(self):
        self.assertFalse(valid_log("\n".join(self.lines + [MARKERS[0] + "=FAIL"])))

    def test_order(self):
        self.assertFalse(valid_log("\n".join(reversed(self.lines))))

    def test_whitespace(self):
        self.assertFalse(valid_log("\n".join(self.lines + [" " + MARKERS[0] + "=FAIL"])))

if __name__ == "__main__":
    unittest.main()
