"""Synthetic tests for the bounded ART boot image attempt."""
from pathlib import Path
import struct
import sys
import tempfile
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"build"))
import r800_wear51_art_boot_probe as probe

class BootProbeTests(unittest.TestCase):
    def test_exact_classpath_order(self):
        paths=[probe.ART_ROOT+"/javalib/"+n for n in probe.BOOT_JARS]
        args=probe.arguments(paths)
        self.assertIn("--compiler-filter=verify",args)
        self.assertIn("--image=/data/boot.art",args)
        self.assertEqual([x for x in args if x.startswith("--dex-file=")],
                         ["--dex-file="+p for p in paths])
        with self.assertRaises(ValueError):
            probe.arguments(paths[::-1])
        speed=probe.arguments(paths,compiler_filter="speed")
        self.assertEqual(speed,[x.replace("--compiler-filter=verify","--compiler-filter=speed") for x in args])
        with self.assertRaises(ValueError):
            probe.arguments(paths,compiler_filter="everything")

    def test_observe_headers(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            (root/"boot.art").write_bytes(b"art\n123\0"+b"\0"*16)
            (root/"boot.vdex").write_bytes(b"vdex123\0"+b"\0"*16)
            oat=bytearray(128)
            oat[:7]=b"\x7fELF\x01\x01\x01"
            struct.pack_into("<HH",oat,16,3,40)
            struct.pack_into("<I",oat,28,52)
            struct.pack_into("<HHH",oat,40,52,32,1)
            struct.pack_into("<8I",oat,52,1,84,0x1000,0,44,44,5,1)
            oat[84:88]=b"oat\n"
            (root/"boot.oat").write_bytes(oat)
            rows=probe.inspect_outputs(root)
            self.assertTrue(all(v["status"]=="HEADER_OBSERVED" for v in rows.values()))
            self.assertEqual(rows["boot.oat"]["elf_segments"]["executable_file_bytes"],44)
            self.assertFalse(rows["boot.oat"]["elf_segments"]["machine_code_validated"])
            struct.pack_into("<I",oat,52+16,1000)
            (root/"boot.oat").write_bytes(oat)
            self.assertEqual(probe.inspect_outputs(root)["boot.oat"]["status"],"REVIEW_REQUIRED")

    def test_reject_empty_and_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            (root/"boot.art").touch()
            (root/"boot.vdex").symlink_to(root/"boot.art")
            rows=probe.inspect_outputs(root)
            self.assertEqual(rows["boot.art"]["status"],"REVIEW_REQUIRED")
            self.assertEqual(rows["boot.vdex"]["status"],"REVIEW_REQUIRED")
            self.assertEqual(rows["boot.oat"]["status"],"NOT_FOUND")

if __name__=="__main__":
    unittest.main()
