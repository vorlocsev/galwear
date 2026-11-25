"""Host staging tests; synthetic file contents, no ELF execution."""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "build"))
from r800_stage_gps_donors import LIBS, stage


def resolve(root, guest):
    return root / guest.lstrip("/"), guest


def validate(raw):
    return {"soname": raw.decode().split(":")[0]}


class StageTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.root = self.base / "donor"
        (self.root / "lib").mkdir(parents=True)
        (self.root / "usr/lib").mkdir(parents=True)
        self.output = self.base / "staged"
        for name in LIBS:
            (self.root / "lib" / name).write_bytes(name.encode())

    def run_stage(self):
        return stage(self.root, self.output, resolve, validate)

    def test_staging_and_hashes(self):
        report = self.run_stage()
        self.assertEqual(report, json.loads((self.output / "manifest.json").read_text()))
        for name in LIBS:
            self.assertEqual((self.output / name).read_bytes(), name.encode())
            self.assertEqual(report["files"][name]["sha256"], hashlib.sha256(name.encode()).hexdigest())
        self.assertFalse(report["safe_to_flash"])
        self.assertFalse(report["donor_authenticity_verified"])

    def test_missing(self):
        (self.root / "lib" / LIBS[0]).unlink()
        with self.assertRaisesRegex(ValueError, "Missing donor"):
            self.run_stage()
        self.assertFalse(self.output.exists())

    def test_conflict(self):
        (self.root / "usr/lib" / LIBS[0]).write_bytes((LIBS[0] + ":different").encode())
        with self.assertRaisesRegex(ValueError, "Conflicting donor"):
            self.run_stage()
        self.assertFalse(self.output.exists())

    def test_identical_duplicate(self):
        (self.root / "usr/lib" / LIBS[0]).write_bytes(LIBS[0].encode())
        self.assertEqual(self.run_stage()["files"][LIBS[0]]["guest_path"], "/lib/" + LIBS[0])

    def test_wrong_soname(self):
        (self.root / "lib" / LIBS[0]).write_bytes(b"wrong")
        with self.assertRaisesRegex(ValueError, "Unexpected SONAME"):
            self.run_stage()

    def test_existing_output(self):
        self.output.mkdir()
        with self.assertRaisesRegex(ValueError, "Output already exists"):
            self.run_stage()

    def test_output_inside_root(self):
        self.output = self.root / "staged"
        with self.assertRaisesRegex(ValueError, "outside"):
            self.run_stage()

    def test_unresolved_symlink(self):
        path = self.root / "lib" / LIBS[0]
        path.unlink()
        path.symlink_to(self.root / "lib" / LIBS[1])
        with self.assertRaises(OSError):
            self.run_stage()


if __name__ == "__main__":
    unittest.main()
