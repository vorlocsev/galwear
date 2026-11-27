"""Exercise the actual post-patch IKHEADERS generator on synthetic files."""
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "build"))
import r800_kheaders_repro as repro


class KheadersReproTests(unittest.TestCase):
    def test_exact_patched_generator_required(self):
        for data in (b"other generator", repro.EXPECTED + b"\n", repro.REPLACEMENT):
            with self.assertRaises(ValueError):
                repro.normalize(data)
        self.assertEqual(repro.normalize(repro.EXPECTED), repro.REPLACEMENT)

    def test_two_archives_match_and_preserve_placeholder(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            script = root / "kernel/gen_kheaders.sh"
            script.parent.mkdir()
            script.write_bytes(repro.EXPECTED)
            repro.apply(root)
            a, b = root / "a.tar.xz", root / "b.tar.xz"
            for output, epoch, zone in ((a, "1", "UTC"), (b, "123456789", "Pacific/Honolulu")):
                subprocess.run(["bash", str(script), str(output)], check=True,
                               env=dict(os.environ, SOURCE_DATE_EPOCH=epoch, TZ=zone))
            self.assertEqual(a.read_bytes(), b.read_bytes())
            with tarfile.open(a, "r:xz") as archive:
                self.assertEqual(archive.getnames(), ["dummy"])
                member = archive.getmember("dummy")
                self.assertTrue(member.isfile())
                self.assertEqual((member.size, member.mtime, member.uid, member.gid, member.mode),
                                 (0, 0, 0, 0, 0o644))
                self.assertEqual(archive.extractfile(member).read(), b"")


if __name__ == "__main__":
    unittest.main()
