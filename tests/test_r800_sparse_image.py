"""Synthetic Android sparse image fixtures."""
import pathlib
import struct
import sys
import tempfile
import unittest
import zlib
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]/"build"))
from r800_sparse_image import convert, MAGIC, RAW, FILL, SKIP, CRC

def chunk(kind, blocks, data=b""):
    return struct.pack("<2H2I",kind,0,blocks,12+len(data))+data

def fixture(chunks, blocks=3, crc=0):
    return struct.pack("<I4H4I",MAGIC,1,0,28,12,4096,blocks,len(chunks),crc)+b"".join(chunks)

class SparseTests(unittest.TestCase):
    def setUp(self):
        t=tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        self.src=pathlib.Path(t.name)/"sparse"
        self.out=pathlib.Path(t.name)/"raw"

    def run_image(self,data):
        self.src.write_bytes(data)
        return convert(self.src,self.out)

    def test_mixed_chunks(self):
        raw=b"x"*4096+b"ABCD"*1024+bytes(4096)
        crc=zlib.crc32(raw)
        result=self.run_image(fixture([chunk(RAW,1,b"x"*4096),chunk(FILL,1,b"ABCD"),
                                       chunk(SKIP,1),chunk(CRC,0,struct.pack("<I",crc))],crc=crc))
        self.assertEqual(self.out.read_bytes(),raw)
        self.assertEqual(result["bytes"],len(raw))
        self.assertFalse(result["safe_to_flash"])

    def test_bad_crc(self):
        with self.assertRaisesRegex(ValueError,"CRC"):
            self.run_image(fixture([chunk(SKIP,3),chunk(CRC,0,bytes(4))]))
        self.assertFalse(self.out.exists())

    def test_truncated_raw(self):
        with self.assertRaisesRegex(ValueError,"Truncated"):
            self.run_image(fixture([chunk(RAW,3,b"x"*12288)])[:-1])

    def test_overflow(self):
        with self.assertRaisesRegex(ValueError,"geometry"):
            self.run_image(fixture([chunk(SKIP,4)]))

    def test_trailing_data(self):
        with self.assertRaisesRegex(ValueError,"trailing"):
            self.run_image(fixture([chunk(SKIP,3)])+b"x")

    def test_invalid_fill(self):
        with self.assertRaisesRegex(ValueError,"FILL"):
            self.run_image(fixture([chunk(FILL,3,b"x")]))

    def test_no_overwrite(self):
        self.out.write_bytes(b"keep")
        with self.assertRaisesRegex(ValueError,"already exists"):
            self.run_image(fixture([chunk(SKIP,3)]))
        self.assertEqual(self.out.read_bytes(),b"keep")

if __name__=="__main__":
    unittest.main()
