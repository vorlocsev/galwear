"""ABI parser and actual synthetic AArch64 ELF smoke tests, no donor execution."""
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"build"))
import r800_ext4_elf_abi as a

CONSUMER = """Symbol table '.dynsym' contains 3 entries:
  0: 0000000000000000 0 NOTYPE LOCAL DEFAULT UND
  1: 0000000000000000 0 FUNC GLOBAL DEFAULT UND fixture@GALWEAR_1 (2)
  2: 0000000000000000 0 FUNC WEAK DEFAULT UND optional
Version needs section '.gnu.version_r' contains 1 entry:
  000000: Version: 1 File: libfixture.so Cnt: 1
  0x0010: Name: GALWEAR_1 Flags: none Version: 2
 0x0000000000000017 (JMPREL) 0x2c8
00000000000084a8  0000000100000402 R_AARCH64_JUMP_SLOT 0000000000000000 fixture@GALWEAR_1 + 0
"""
PROVIDER = """Symbol table '.dynsym' contains 2 entries:
  0: 0000000000000000 0 NOTYPE LOCAL DEFAULT UND
  1: 00000000000042f4 8 FUNC GLOBAL DEFAULT 8 fixture@@GALWEAR_1
"""

class AbiTests(unittest.TestCase):
    def test_import_provider_and_version(self):
        row=a.parse(CONSUMER)["imports"][0]
        self.assertEqual((row["provider"],row["version"]),("libfixture.so","GALWEAR_1"))
        self.assertTrue(a.matches(row,a.parse(PROVIDER)["exports"][0]))

    def test_weak_and_relocation(self):
        result=a.parse(CONSUMER)
        self.assertTrue(result["imports"][1]["weak"])
        self.assertEqual(result["relocation_tags"],["JMPREL"])
        self.assertEqual(result["visible_relocation_types"],["R_AARCH64_JUMP_SLOT"])

    def test_bad_version_and_incomplete_table(self):
        for text in (CONSUMER.replace("Version: 2","Version: 3"),
                     CONSUMER.replace("contains 3 entries","contains 4 entries")):
            with self.assertRaises(ValueError):
                a.parse(text)

    def test_unsupported_relocation_encoding(self):
        for tag in ("0x0000000000000016 (TEXTREL) 0x0",
                    "0x000000006000000f (UNKNOWN) 0x0",
                    "0x000000000000001e (FLAGS) TEXTREL"):
            with self.assertRaises(ValueError):
                a.parse(CONSUMER+"\n"+tag)

    def test_android_packed_tags_are_not_empty_relocations(self):
        text=CONSUMER+"\n0x0000000060000011 (Operating System specific: 60000011) 0x290\n"
        text+="0x0000000060000012 (Operating System specific: 60000012) 0x1b\n"
        self.assertTrue({"ANDROID_RELA","ANDROID_RELASZ"}<=set(a.parse(text)["relocation_tags"]))

    def test_version_tls_mismatch(self):
        need=a.parse(CONSUMER)["imports"][0]
        exp=a.parse(PROVIDER)["exports"][0]
        self.assertFalse(a.matches(need,{**exp,"version":"GALWEAR_2"}))
        self.assertFalse(a.matches(need,{**exp,"type":"TLS"}))

    def test_nondefault_export_for_unversioned_import(self):
        exp=a.parse(PROVIDER.replace("@@","@"))["exports"][0]
        self.assertFalse(a.matches({"name":"fixture","version":None,"type":"FUNC"},exp))

    def test_provider_identity_and_weak_accounting(self):
        root,lib,link="/system/bin/service","/system/lib64/libfixture.so","/system/bin/linker64"
        def obj(text,h,soname):
            return {**a.parse(text),"sha256":h,"soname":soname}
        objects={root:obj(CONSUMER,"a","service"),
                 lib:obj(PROVIDER,"b","libfixture.so"),
                 link:obj(PROVIDER,"c","other.so")}
        closure={root:{"selected_elf_sha256":{root:"a",lib:"b"},
                       "interpreter":link,"interpreter_sha256":"c"}}
        result=a.summarize(closure,objects)[root]
        self.assertEqual(result["missing_strong_candidates"],0)
        self.assertEqual(result["missing_weak_candidates"],1)
        objects[lib]["soname"]="wrong.so"
        self.assertEqual(a.summarize(closure,objects)[root]["missing_strong_candidates"],1)

    @unittest.skipUnless(all(shutil.which(x) for x in ("clang","ld.lld","readelf")),
                         "cross-target clang/lld and GNU readelf required")
    def test_real_aarch64_versioned_elf(self):
        with tempfile.TemporaryDirectory(prefix="galwear-abi-test-") as tmp:
            d=Path(tmp)
            (d/"a.c").write_text("int fixture(void){return 3;}\n")
            (d/"b.c").write_text("extern int fixture(void); int call(void){return fixture();}\n")
            (d/"version.map").write_text("GALWEAR_1 { global: fixture; local: *; };\n")
            common=["clang","--target=aarch64-linux-android30","-fuse-ld=lld","-nostdlib","-shared"]
            subprocess.run([*common,"-Wl,-soname,libfixture.so",
                            "-Wl,--version-script="+str(d/"version.map"),"-o",str(d/"libfixture.so"),
                            str(d/"a.c")],check=True,capture_output=True,timeout=30)
            subprocess.run([*common,"-Wl,-soname,libconsumer.so","-L"+tmp,"-lfixture",
                            "-o",str(d/"libconsumer.so"),str(d/"b.c")],
                           check=True,capture_output=True,timeout=30)
            lib=a.inspect(d/"libfixture.so")
            consumer=a.inspect(d/"libconsumer.so")
            need=next(x for x in consumer["imports"] if x["name"]=="fixture")
            self.assertEqual(need["provider"],"libfixture.so")
            self.assertTrue(any(a.matches(need,x) for x in lib["exports"]))
            self.assertIn("R_AARCH64_JUMP_SLOT",consumer["visible_relocation_types"])

if __name__=="__main__":
    unittest.main()
