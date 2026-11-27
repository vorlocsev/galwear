import sys
import tempfile
import unittest
from pathlib import Path
import subprocess

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "build"))
import r800_vendor_recipe_preflight as p


class VendorRecipePreflightTests(unittest.TestCase):
    def test_real_ext4_recipe_selection_and_missing_group(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            images = {}
            for name, fixed in (("base", p.BASE_PATHS), ("j4", p.J4_PATHS)):
                tree = root/name
                tree.mkdir()
                selected = set(fixed)
                if name == "base":
                    selected.update(p.GROUPS["wifi"])
                    selected.update(p.GROUPS["gnss"][:2])
                else:
                    selected.update(p.GROUPS["sensors"])
                    selected.update(p.GROUPS["gnss"][2:])
                for rel in sorted(selected):
                    dest = tree/rel
                    if rel in p.DIRECTORIES:
                        dest.mkdir(parents=True, exist_ok=True)
                    else:
                        dest.parent.mkdir(parents=True, exist_ok=True)
                        dest.write_bytes(b"synthetic")
                image = root/(name+".img")
                with image.open("wb") as stream:
                    stream.truncate(16*1024**2)
                subprocess.run(["mke2fs", "-q", "-F", "-t", "ext4", "-d", str(tree), str(image)],
                               check=True, capture_output=True)
                images[name] = image
            a, b = images["base"], images["j4"]
            before = [p.image_info(a), p.image_info(b)]
            report = p.audit(a, before[0]["sha256"], b, before[1]["sha256"])
            self.assertEqual(report["blockers"], ["hidl:gnss"])
            self.assertEqual(report["hidl_groups"]["wifi"]["selected"], "base")
            self.assertEqual(report["hidl_groups"]["sensors"]["selected"], "j4")
            self.assertIsNone(report["hidl_groups"]["gnss"]["selected"])
            self.assertEqual([p.image_info(a), p.image_info(b)], before)
            self.assertFalse(report["safe_to_flash"])
            with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
                p.audit(a, "0"*64, b, before[1]["sha256"])


if __name__ == "__main__":
    unittest.main()
