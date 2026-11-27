import sys
import tempfile
import unittest
from pathlib import Path
import shutil
import subprocess

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "build"))
import r800_compiled_overlay_ext4 as overlay


class OverlayMetadataTests(unittest.TestCase):
    def test_real_ext4_metadata_and_negative_cases(self):
        for tool in ("mke2fs", "debugfs", "e2fsck"):
            self.assertIsNotNone(shutil.which(tool), tool)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            tree = root/"tree"
            (tree/"lib/hw").mkdir(parents=True)
            (tree/"etc").mkdir()
            (tree/"lib/hw/fixture.so").write_bytes(b"synthetic HAL")
            (tree/"etc/fixture.rc").write_bytes(b"synthetic config")
            rows = {p: {"sha256": overlay.sha((tree/p).read_bytes())}
                    for p in ("lib/hw/fixture.so", "etc/fixture.rc")}
            entries = overlay.metadata_plan(tree, rows)
            image = root/"fixture.ext4"
            with image.open("wb") as f:
                f.truncate(16*1024**2)
            subprocess.run(["mke2fs", "-q", "-F", "-t", "ext4", "-d", str(tree), str(image)],
                           check=True, capture_output=True)
            overlay.apply_metadata(image, entries, root, "debugfs")
            subprocess.run(["e2fsck", "-fn", str(image)], check=True, capture_output=True)
            before = overlay.image_info(image)
            report = overlay.verify_metadata(image, entries, root, "debugfs")
            self.assertEqual(report["/lib/hw/fixture.so"]["context"], "u:object_r:vendor_file:s0")
            self.assertEqual(report["/etc/fixture.rc"]["context"], "u:object_r:vendor_configs_file:s0")
            self.assertEqual(report["/"]["uid"], 0)
            self.assertEqual(overlay.image_info(image), before)
            def write(request):
                subprocess.run(["debugfs", "-w", "-R", request, str(image)],
                               check=True, capture_output=True)
            write("set_inode_field /etc/fixture.rc mode 0100666")
            with self.assertRaisesRegex(ValueError, "inode mode"):
                overlay.verify_metadata(image, entries, root, "debugfs")
            write("set_inode_field /etc/fixture.rc mode 0100644")
            write("set_inode_field /etc/fixture.rc gid 1000")
            with self.assertRaisesRegex(ValueError, "ownership"):
                overlay.verify_metadata(image, entries, root, "debugfs")
            write("set_inode_field /etc/fixture.rc gid 0")
            write("ea_rm /etc/fixture.rc security.selinux")
            with self.assertRaises((ValueError, OSError, subprocess.SubprocessError)):
                overlay.verify_metadata(image, entries, root, "debugfs")


if __name__ == "__main__":
    unittest.main()
