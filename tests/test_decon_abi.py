"""Test extraction and rejection before cross-compilation."""
import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "build"))
from r800_decon_abi_check import extract, generate, MAPPING


class DeconAbiTests(unittest.TestCase):
    def setUp(self):
        self.mirror = (ROOT / "src/hal/r800_decon_abi.h").read_text()
        source = self.mirror.split("_Static_assert", 1)[0]
        for old, new in sorted(MAPPING.items(), key=lambda x: -len(x[1])):
            source = source.replace(new, old)
        self.kernel = source.replace("R800_MAX_DECON_WIN", "MAX_DECON_WIN").replace(
            "R800_S3CFB_WIN_CONFIG _IOW('F', 209, struct decon_win_config_data)",
            "S3CFB_WIN_CONFIG _IOW('F', 209, \\\n struct decon_win_config_data)") + "\n#define MAX_PLANE_CNT 3\n"

    def test_nested_union(self):
        self.assertIn("int acq_fence;", extract(self.kernel, "decon_win_config"))

    def test_generated_assertions(self):
        output = generate(self.kernel, self.mirror)
        self.assertIn("sizeof(struct decon_win_config_data) == 808", output)
        self.assertIn("S3CFB_WIN_CONFIG == 0x432846d1UL", output)

    def test_changed_window_count(self):
        with self.assertRaises(ValueError):
            generate(self.kernel.replace("MAX_DECON_WIN\t3", "MAX_DECON_WIN\t4"), self.mirror)

    def test_changed_ioctl(self):
        with self.assertRaises(ValueError):
            generate(self.kernel.replace("'F', 209", "'F', 210"), self.mirror)

    def test_missing_structure(self):
        with self.assertRaises(ValueError):
            extract("struct unrelated { int x; };", "decon_frame")


if __name__ == "__main__":
    unittest.main()
