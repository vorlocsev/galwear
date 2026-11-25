"""Relocation decoding regressions and real synthetic AArch64 linker output."""
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"build"))
import r800_elf_relocations as a


def encode(value):
    out=bytearray()
    while True:
        b=value&127
        value>>=7
        if (value==0 and not b&64) or (value==-1 and b&64):
            out.append(b)
            return bytes(out)
        out.append(b|128)


def packed(*values):
    return b"APS2"+b"".join(map(encode,values))


def fixture(table, tags, addr=0x1000, flags=6):
    # Minimal synthetic ELF, two non-overlapping LOADs, PT_DYNAMIC in RO LOAD.
    data=bytearray(0x500)
    data[:16]=b"\x7fELF\x02\x01\x01"+bytes(9)
    struct.pack_into("<HHIQQQIHHHHHH",data,16,3,183,1,0,64,0,0,64,56,3,0,0,0)
    dyn=b"".join(struct.pack("<qQ",k,v) for k,v in [*tags,(0,0)])
    struct.pack_into("<IIQQQQQQ",data,64,1,4,0,0,0,0x400,0x400,0x1000)
    struct.pack_into("<IIQQQQQQ",data,120,1,flags,0x400,addr,addr,0x100,0x100,0x1000)
    struct.pack_into("<IIQQQQQQ",data,176,2,4,0x180,0x180,0x180,len(dyn),len(dyn),8)
    data[0x180:0x180+len(dyn)]=dyn
    data[0x300:0x300+len(table)]=table
    return bytes(data)


class RelocationTests(unittest.TestCase):
    def test_grouped_and_individual_addends(self):
        # Two grouped offsets, info, delta-addend per group; then one
        # ungrouped entry resets the running addend when HAS_ADDEND is clear.
        rows=list(a.aps2(packed(3,0xff8,2,15,8,1027,9,1,0,8,257)))
        self.assertEqual(rows,[(0x1000,1027,9),(0x1008,1027,9),(0x1010,257,0)])
        self.assertEqual(list(a.aps2(packed(2,0xff8,2,8,8,1027,7,8,1027,-3))),
                         [(0x1000,1027,7),(0x1008,1027,4)])

    def test_bad_aps2(self):
        for raw in (b"bad!",b"APS2\x80",packed(-1,0),packed(1,0,0,0),
                    packed(1,0,2,0),packed(1,0,1,16),
                    packed(1,0,1,4),packed(0,0)+b"\0",b"APS2"+b"\x80"*11):
            with self.subTest(raw=raw),self.assertRaises(ValueError):
                list(a.aps2(raw))

    def test_relr_bitmap_and_boundaries(self):
        self.assertEqual(list(a.relr(struct.pack("<QQQ",0x1000,0b1011,0x1300))),
                         [0x1000,0x1008,0x1018,0x1300])
        for raw in (b"x",struct.pack("<Q",3),struct.pack("<Q",0x1002),
                    struct.pack("<QQ",0x1000,0x1000)):
            with self.assertRaises(ValueError):
                list(a.relr(raw))

    def test_actual_elf_target_and_symbol_bounds(self):
        def image(offset=0x1000,info=1027,flags=6):
            raw=struct.pack("<QQq",offset,info,0)
            return fixture(raw,[(7,0x300),(8,24),(9,24)],flags=flags)
        self.assertEqual(a.inspect(image(),2)["relocation_count"],1)
        for blob in (image(offset=0x10fc),image(offset=0x200),image(flags=5),
                     image(info=(2<<32)|257),image(info=1024),image(info=(1<<32)|1027)):
            with self.assertRaises(ValueError):
                a.inspect(blob,2)

    def test_overlap_rejected(self):
        raw=struct.pack("<QQqQQq",0x1000,1031,0,0x1008,1027,0)
        with self.assertRaisesRegex(ValueError,"Overlapping relocation targets"):
            a.inspect(fixture(raw,[(7,0x300),(8,48),(9,24)]),2)

    def test_malformed_dynamic_tags(self):
        raw=struct.pack("<QQq",0x1000,1027,0)
        for tags in ([(7,0x300)],[(7,0x300),(8,23)],[(7,0x300),(7,0x300),(8,24)],
                     [(7,0x300),(8,24),(9,16)],[(7,0x500),(8,24)],
                     [(17,0x300),(18,24)],[(22,0)]):
            with self.assertRaises(ValueError):
                a.inspect(fixture(raw,tags),2)

    def test_both_relr_encodings(self):
        raw=struct.pack("<QQ",0x1000,7)
        for tags in ([(36,0x300),(35,16),(37,8)],
                     [(0x6fffe000,0x300),(0x6fffe001,16),(0x6fffe003,8)]):
            self.assertEqual(a.inspect(fixture(raw,tags),2)["counts_by_encoding_and_type"],
                             {"RELR:RELATIVE":3})

    def test_aps2_from_dynamic(self):
        raw=packed(2,0xff8,2,3,8,1027)
        result=a.inspect(fixture(raw,[(0x60000011,0x300),(0x60000012,len(raw))]),2)
        self.assertEqual(result["counts_by_encoding_and_type"],{"APS2:RELATIVE":2})
        self.assertFalse(result["relocations_applied"])

    @unittest.skipUnless(all(shutil.which(x) for x in ("clang","ld.lld","readelf")),
                         "cross-target clang/lld and GNU readelf required")
    def test_real_aarch64_relocation_encodings(self):
        import r800_ext4_elf_abi as abi
        with tempfile.TemporaryDirectory() as tmp:
            d=Path(tmp)
            source=d/"fixture.c"
            source.write_text("static int x; void *p[]={&x,&x,&x,&x}; extern int ext; void *q=&ext;\n")
            for mode,expected in (
                ("none",{"RELA:RELATIVE":4,"RELA:ABS64":1}),
                ("android",{"APS2:RELATIVE":4,"APS2:ABS64":1}),
                ("relr",{"RELR:RELATIVE":4,"RELA:ABS64":1}),
                ("android+relr",{"RELR:RELATIVE":4,"APS2:ABS64":1})):
                with self.subTest(mode=mode):
                    elf=d/(mode+".so")
                    subprocess.run(["clang","--target=aarch64-linux-android30","-fuse-ld=lld",
                                    "-nostdlib","-shared","-Wl,--pack-dyn-relocs="+mode,
                                    "-o",str(elf),str(source)],check=True,capture_output=True,timeout=30)
                    result=abi.inspect(elf)["relocation_structure"]
                    self.assertEqual(result["counts_by_encoding_and_type"],expected)
                    self.assertEqual(result["relocation_count"],5)

if __name__=="__main__":
    unittest.main()
