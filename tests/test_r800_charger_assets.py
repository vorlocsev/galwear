"""Generate actual raw assets from synthetic input, never original firmware."""
import hashlib
import io
import json
from pathlib import Path
import shutil
import struct
import subprocess
import tarfile
import tempfile
import unittest
import zipfile
import zlib

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "src/tools/charger/mkassets.sh"
FONT = Path("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf")
SIZES = {"splash.raw": 360*360*4, "charger/pct.rgb": 36*110*3,
         "charger/bolt.rgb": 80*60*3}
SIZES.update({"charger/d%d.rgb" % i: 55*110*3 for i in range(10)})


def png(w=2, h=2):
    def chunk(tag, data):
        return struct.pack(">I", len(data))+tag+data+struct.pack(">I", zlib.crc32(tag+data))
    return (b"\x89PNG\r\n\x1a\n" +
            chunk(b"IHDR",struct.pack(">IIBBBBB",w,h,8,2,0,0,0)) +
            chunk(b"IDAT", zlib.compress((b"\0"+b"\x12\x34\x56"*w)*h)) +
            chunk(b"IEND",b""))


@unittest.skipUnless((shutil.which("magick") or shutil.which("convert")) and FONT.is_file(),
                     "ImageMagick or DejaVu test font unavailable")
class ChargerAssetsTests(unittest.TestCase):
    def setUp(self):
        t = tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        self.root = Path(t.name)
        self.param = self.root/"param.bin"
        self.animation = self.root/"bootanimation.zip"
        self.out = self.root/"assets"
        self.prepare()

    def prepare(self, duplicate=False, bad_digit=False, wide=False):
        with tarfile.open(self.param,"w") as tar:
            for i in range(10):
                name = "pow_digital_num_%d.raw" % i
                data = bytes([i])* (1 if i==0 and bad_digit else 55*110*3)
                m = tarfile.TarInfo(name)
                m.size = len(data)
                tar.addfile(m,io.BytesIO(data))
                if duplicate and i==0:
                    tar.addfile(m,io.BytesIO(data))
        with zipfile.ZipFile(self.animation,"w") as z:
            z.writestr("part1/00000.png",png(2049,1) if wide else png())
            z.writestr("../../ignored",b"not extracted")

    def generate(self):
        return subprocess.run(["sh",str(SCRIPT),str(self.param),str(self.animation),
                               str(self.out),str(FONT)],capture_output=True,text=True,timeout=45)

    def test_actual_raw_generation(self):
        result = self.generate()
        self.assertEqual(result.returncode,0,result.stderr)
        evidence = json.loads((self.out/"assets-evidence.json").read_text())
        self.assertEqual(set(evidence),set(SIZES))
        for name,size in SIZES.items():
            raw = (self.out/name).read_bytes()
            self.assertEqual(len(raw),size)
            self.assertEqual(evidence[name]["sha256"],hashlib.sha256(raw).hexdigest())
        for i in range(10):
            self.assertEqual((self.out/"charger"/("d%d.rgb"%i)).read_bytes(),bytes([i])*(55*110*3))
        splash = (self.out/"splash.raw").read_bytes()
        self.assertEqual(splash[:4],b"\0\0\0\xff")
        self.assertEqual(splash[(179*360+179)*4:(179*360+179)*4+4],b"\x56\x34\x12\xff")

    def test_duplicate_digit_rejected(self):
        self.prepare(duplicate=True)
        self.assertNotEqual(self.generate().returncode,0)
        self.assertFalse(self.out.exists())

    def test_wrong_digit_size_rejected(self):
        self.prepare(bad_digit=True)
        self.assertNotEqual(self.generate().returncode,0)
        self.assertFalse(self.out.exists())

    def test_oversize_frame_rejected(self):
        self.prepare(wide=True)
        self.assertNotEqual(self.generate().returncode,0)
        self.assertFalse(self.out.exists())

    def test_no_overwrite(self):
        self.out.mkdir()
        (self.out/"keep").write_text("original")
        self.assertNotEqual(self.generate().returncode,0)
        self.assertEqual((self.out/"keep").read_text(),"original")

if __name__=="__main__":
    unittest.main()
