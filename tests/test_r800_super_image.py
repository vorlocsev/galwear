"""Synthetic single-device Android logical partition image."""
import hashlib
import pathlib
import struct
import sys
import tempfile
import unittest
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/"build"))
from r800_super_image import run

def fixture(target=40):
    data=bytearray(65536)
    geo=bytearray(struct.pack("<II32sIII",0x616c4467,52,bytes(32),4096,1,4096))
    geo[8:40]=hashlib.sha256(geo).digest()
    for off in (4096,8192):
        data[off:off+52]=geo
    tables=[
        struct.pack("<36sIIII",b"system_a",1,0,2,0),
        struct.pack("<QIQI",8,0,target,0)+struct.pack("<QIQI",8,1,0,0),
        struct.pack("<36sIQ",b"default",0,0),
        struct.pack("<QIIQ36sI",40,4096,0,len(data),b"super",0)]
    body=b"".join(tables)
    hdr=bytearray(128)
    struct.pack_into("<IHHI",hdr,0,0x414c5030,10,0,128)
    struct.pack_into("<I",hdr,44,len(body))
    hdr[48:80]=hashlib.sha256(body).digest()
    pos=0
    for i,(table,entry) in enumerate(zip(tables,(52,24,48,64))):
        struct.pack_into("<III",hdr,80+i*12,pos,len(table)//entry,entry)
        pos+=len(table)
    hdr[12:44]=hashlib.sha256(hdr).digest()
    for off in (12288,16384):
        data[off:off+len(hdr)+len(body)]=hdr+body
    data[40*512:48*512]=b"x"*4096
    return data

class SuperTests(unittest.TestCase):
    def setUp(self):
        t=tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        self.src=pathlib.Path(t.name)/"super"
        self.out=pathlib.Path(t.name)/"system"
        self.src.write_bytes(fixture())

    def test_inspect(self):
        r=run(self.src,0)
        self.assertEqual(r["partitions"]["system_a"]["bytes"],8192)
        self.assertFalse(r["safe_to_flash"])

    def test_extract(self):
        run(self.src,0,"system_a",self.out)
        self.assertEqual(self.out.read_bytes(),b"x"*4096+bytes(4096))

    def test_invalid_backup(self):
        data=fixture()
        data[16384+48]^=1
        self.src.write_bytes(data)
        with self.assertRaisesRegex(ValueError,"checksum"):
            run(self.src,0)

    def test_out_of_range(self):
        self.src.write_bytes(fixture(32))
        with self.assertRaisesRegex(ValueError,"out-of-range"):
            run(self.src,0)

    def test_invalid_slot(self):
        with self.assertRaisesRegex(ValueError,"slot"):
            run(self.src,1)

    def test_disallowed_partition(self):
        with self.assertRaisesRegex(ValueError,"allowlist"):
            run(self.src,0,"userdata",self.out)

if __name__=="__main__":
    unittest.main()
