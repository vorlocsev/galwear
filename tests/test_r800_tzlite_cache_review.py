"""Synthetic glibc 2.24 cache tables and strict bounds."""
from pathlib import Path
import struct
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"build"))
from r800_tzlite_cache_review import parse_ld, parse_gconv, classify, OLD, NEW


def new_cache(name=b"libfixture.so.1",path=b"/usr/lib/libfixture.so.1"):
    strings=name+b"\0"+path+b"\0"
    return NEW+struct.pack("<II5I",1,len(strings),0,0,0,0,0)+struct.pack(
        "<iIIIQ",3,72,73+len(name),0,0)+strings


def gconv_cache(*,chains=False):
    strings=bytearray(b"\0")
    def add_string(value):
        offset=len(strings)
        strings.extend(value+b"\0")
        return offset
    canon=add_string(b"INTERNAL")
    directory=add_string(b"/usr/lib/gconv/")
    module=add_string(b"UTF-16.so")
    other_name=add_string(b"EXTRA.so") if chains else 0
    second=add_string(b"UTF-16//") if chains else 0
    strings=bytes(strings)
    if len(strings)%2:
        strings+=b"\0"
    hashes=16+len(strings)
    modules=hashes+12
    extra=modules+(24 if chains else 12)
    raw=struct.pack("<I5H",0x20010324,16,hashes,3,modules,extra)+b"\0\0"+strings+struct.pack(
        "<6H",canon,0,0,0,0,0)+struct.pack("<6H",canon,directory,module,0,0,0)
    if chains:
        raw+=struct.pack("<6H",second,0,0,0,0,1)
        raw+=struct.pack("<5H",1,0,directory,other_name,0)
    return raw


class CacheTests(unittest.TestCase):
    def test_new(self):
        fmt,rows=parse_ld(new_cache())
        self.assertEqual(fmt,"GLIBC_2_24_NEW")
        self.assertEqual(rows[0][:2],("libfixture.so.1","/usr/lib/libfixture.so.1"))
    def test_old(self):
        strings=b"lib.so\0/usr/lib/lib.so\0"
        raw=OLD+b"\0"+struct.pack("<I",1)+struct.pack("<iII",3,0,7)+strings
        self.assertEqual(parse_ld(raw)[0],"LEGACY_ONLY")
    def test_compat(self):
        raw=OLD+b"\0"+struct.pack("<I",1)+b"\0"*16+new_cache()
        self.assertEqual(parse_ld(raw)[0],"GLIBC_2_24_COMPAT_NEW")
    def test_bad_offset(self):
        raw=bytearray(new_cache())
        struct.pack_into("<I",raw,52,1)
        with self.assertRaises(ValueError):
            parse_ld(raw)
    def test_unsafe_path(self):
        with self.assertRaises(ValueError):
            parse_ld(new_cache(path=b"/usr/lib/../lib.so"))
    def test_gconv(self):
        self.assertEqual(parse_gconv(gconv_cache())["module_paths"],["/usr/lib/gconv/UTF-16.so"])
    def test_gconv_empty_module_name(self):
        raw=bytearray(gconv_cache())
        modules=struct.unpack_from("<H",raw,10)[0]
        struct.pack_into("<H",raw,modules+4,0)
        with self.assertRaises(ValueError):
            parse_gconv(raw)
    def test_gconv_bad_hash(self):
        raw=bytearray(gconv_cache())
        hashes=struct.unpack_from("<H",raw,6)[0]
        struct.pack_into("<H",raw,hashes+2,9)
        with self.assertRaises(ValueError):
            parse_gconv(raw)
    def test_gconv_extra_chain(self):
        report=parse_gconv(gconv_cache(chains=True))
        self.assertTrue(report["extra_chains_parsed"])
        self.assertEqual(report["extra_chain_count"],1)
        self.assertEqual(report["extra_step_count"],1)
        self.assertEqual(report["extra_module_paths"],["/usr/lib/gconv/EXTRA.so"])
        self.assertIn("/usr/lib/gconv/EXTRA.so",report["module_paths"])
        self.assertFalse(report["hash_lookup_verified"])
    def test_gconv_extra_bad_index(self):
        raw=bytearray(gconv_cache(chains=True))
        extra=struct.unpack_from("<H",raw,12)[0]
        struct.pack_into("<H",raw,extra+2,2)
        with self.assertRaises(ValueError):
            parse_gconv(raw)
    def test_gconv_extra_unterminated(self):
        with self.assertRaises(ValueError):
            parse_gconv(gconv_cache(chains=True)[:-2])
    def test_gconv_extra_bad_offset(self):
        raw=bytearray(gconv_cache(chains=True))
        modules=struct.unpack_from("<H",raw,10)[0]
        struct.pack_into("<H",raw,modules+12+10,3)
        with self.assertRaises(ValueError):
            parse_gconv(raw)
    def test_gconv_extra_budget(self):
        raw=bytearray(gconv_cache(chains=True))
        extra=struct.unpack_from("<H",raw,12)[0]
        struct.pack_into("<H",raw,extra,4097)
        with self.assertRaises(ValueError):
            parse_gconv(raw)
    def test_gconv_unreferenced_tail(self):
        with self.assertRaises(ValueError):
            parse_gconv(gconv_cache()+b"\0\0")
    def test_classification(self):
        closure={"aliases":{"/lib/lib.so":"/usr/lib/lib.so"},
                 "files":{"/usr/lib/lib.so":{"sha256":"a"*64}}}
        self.assertEqual(classify("/lib/lib.so",closure)["status"],"AUDITED_PATH_CANDIDATE")
        self.assertEqual(classify("/opt/lib.so",closure)["status"],"NOT_IN_AUDITED_SUBSET")
        self.assertEqual(classify("/usr/lib/lib.so",closure)["status"],"AUDITED_PATH_CANDIDATE")
        self.assertEqual(classify("/usr/lib/other-alias.so",closure)["status"],"NOT_IN_AUDITED_SUBSET")


if __name__=="__main__":
    unittest.main()
