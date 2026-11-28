"""Regression for the pure .tbss ARM32 Android 15 segment layout."""
import struct
import unittest
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"build"))
from r800_android_linker_audit import inspect


def elf(tls_addr=0x1300,tls_off=0x300,tls_file=0,tls_mem=12,align=4,etype=3):
    data=bytearray(0x500)
    data[:16]=b"\x7fELF\x01\x01\x01"+b"\0"*9
    struct.pack_into("<HHIIIIIHHHHHH",data,16,etype,40,1,0,52,0,0,52,32,2,0,0,0)
    # File-backed LOAD ends at (vaddr 0x1300, offset 0x300).
    struct.pack_into("<IIIIIIII",data,52,1,0,0x1000,0x1000,0x300,0x300,5,0x1000)
    struct.pack_into("<IIIIIIII",data,84,7,tls_off,tls_addr,tls_addr,tls_file,tls_mem,4,align)
    return bytes(data)


class Wear51TlsTests(unittest.TestCase):
    def test_pure_tbss_after_load(self):
        r=inspect(elf())
        self.assertEqual(r["tls_segment"]["file_size"],0)
        self.assertEqual(r["tls_segment"]["memory_size"],12)
        self.assertEqual(r["abi"],"arm")

    def test_initialized_tls_inside_load(self):
        r=inspect(elf(tls_addr=0x1200,tls_off=0x200,tls_file=4))
        self.assertEqual(r["tls_segment"]["file_size"],4)

    def test_initialized_tls_outside_load_rejected(self):
        with self.assertRaisesRegex(ValueError,"outside PT_LOAD"):
            inspect(elf(tls_file=4))

    def test_unanchored_tbss_rejected(self):
        for addr,off in ((0x1400,0x300),(0x1300,0x304)):
            with self.subTest(addr=addr,off=off):
                with self.assertRaisesRegex(ValueError,"outside PT_LOAD"):
                    inspect(elf(tls_addr=addr,tls_off=off))

    def test_invalid_bounds_rejected(self):
        for kwargs in ({"tls_mem":0x4000001},{"etype":2},{"align":3},{"tls_addr":0xfffffffc,"tls_mem":12}):
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(ValueError):
                    inspect(elf(**kwargs))


if __name__=="__main__":
    unittest.main()
