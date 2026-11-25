"""Peripheral firmware contract tests on synthetic bytes, never on hardware."""
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock
import os
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"build"))
from r800_peripheral_firmware import audit, check_bytes, REQUIRED, EXCLUDED

BBD="fw/bbd_patch_mainhub_21091500.txt"
ROOT=Path(__file__).resolve().parents[1]

class PeripheralTests(unittest.TestCase):
    def test_contract_matches_sources(self):
        dts=(ROOT/"src/dt/r800.dts").read_text()
        patch=(ROOT/"src/kernel/r800-wearos.patch").read_text()
        for name in REQUIRED:
            self.assertIn(Path(name).name,dts if name not in (BBD,"fw/vts.bin") else patch)
        self.assertFalse(set(REQUIRED)&{"fw/"+n for n in EXCLUDED})

    def test_missing(self):
        with tempfile.TemporaryDirectory() as t:
            r=audit(Path(t))
            self.assertEqual(set(r["blockers"]),set(REQUIRED))
            self.assertFalse(r["safe_to_flash"])

    def test_structural_only(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t)
            (root/"fw").mkdir()
            for name in REQUIRED:
                (root/name).write_bytes(b"synthetic\0" if name==BBD else b"synthetic")
            r=audit(root)
            self.assertFalse(r["blockers"])
            self.assertFalse(r["hardware_compatibility_verified"])
            self.assertFalse(r["authenticity_verified"])

    def test_bbd_representation(self):
        for raw in (b"",b"\0",b"patch",b"patch\0more\0",b"\xff\0"):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                check_bytes(BBD,raw)
        self.assertEqual(check_bytes(BBD,b"patch\n\0")["bytes"],7)

    def test_symlink_rejected(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t)
            (root/"fw").mkdir()
            (root/"fw/vts.bin").symlink_to("/etc/passwd")
            self.assertEqual(audit(root)["files"]["fw/vts.bin"]["status"],"REJECTED")

    def test_symlink_loop_rejected_without_aborting_audit(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t)
            (root/"fw").mkdir()
            p=root/"fw/vts.bin"
            p.symlink_to(p.name)
            r=audit(root)
            self.assertEqual(r["files"]["fw/vts.bin"]["status"],"REJECTED")
            self.assertEqual(set(r["files"]),set(REQUIRED))
            self.assertFalse(r["safe_to_flash"])

    def test_symlink_directory_rejected(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t)
            (root/"actual").mkdir()
            (root/"actual/vts.bin").write_bytes(b"synthetic")
            (root/"fw").symlink_to("actual",target_is_directory=True)
            self.assertEqual(audit(root)["files"]["fw/vts.bin"]["status"],"REJECTED")

    def test_same_size_and_mtime_replacement_rejected(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t)
            (root/"fw").mkdir()
            p=root/"fw/vts.bin"
            p.write_bytes(b"original")
            s=p.stat()
            replacement=root/"replacement"
            replacement.write_bytes(b"replaced")
            os.utime(replacement,ns=(s.st_atime_ns,s.st_mtime_ns))
            real_open=os.open

            def replace_then_open(path,flags,*args,**kwargs):
                if Path(path)==p and replacement.exists():
                    replacement.replace(p)
                return real_open(path,flags,*args,**kwargs)

            with mock.patch("r800_peripheral_firmware.os.open",side_effect=replace_then_open):
                r=audit(root)
            self.assertEqual(r["files"]["fw/vts.bin"]["status"],"REJECTED")
            self.assertFalse(r["safe_to_flash"])

if __name__=="__main__":
    unittest.main()
