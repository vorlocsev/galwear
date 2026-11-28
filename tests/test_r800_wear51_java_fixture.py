"""Synthetic DEX structure and standalone VM marker controls."""
import struct
import sys
import unittest
from unittest.mock import patch
import tempfile
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"build"))
import r800_wear51_java_fixture as fixture
import r800_wear51_vm_probe as vm
import r800_wear51_art_probe as art
from r800_art_inventory import dex_inventory
from r800_wear51_art_boot_probe import BOOT_JARS, ART_ROOT


class JavaFixtureTests(unittest.TestCase):
    def test_deterministic_dex(self):
        raw=fixture.build()
        self.assertEqual(raw,fixture.build())
        report=dex_inventory(raw)
        self.assertEqual(report["version"],"035")
        self.assertEqual(report["sections"]["class_defs"],1)
        self.assertEqual(report["sections"]["method_ids"],2)
        self.assertEqual(report["sections"]["field_ids"],1)
        self.assertIn(fixture.MARKER.encode()+b"\0",raw)
        self.assertFalse(report["bytecode_verified"])

    def test_code_item_map_and_instructions(self):
        raw=fixture.build()
        off=struct.unpack_from("<I",raw,52)[0]
        n=struct.unpack_from("<I",raw,off)[0]
        entries=[struct.unpack_from("<HHII",raw,off+4+12*i) for i in range(n)]
        self.assertEqual([x[3] for x in entries],sorted(x[3] for x in entries))
        code=next(x for x in entries if x[0]==0x2001)
        self.assertEqual(code[2],1)
        self.assertEqual(struct.unpack_from("<4H2I",raw,code[3]),(3,1,2,0,0,8))
        ops=struct.unpack_from("<8H",raw,code[3]+16)
        self.assertEqual((ops[0],ops[2],ops[4],ops[6],ops[7]),
                         (0x0062,0x011a,0x206e,0x0010,0x000e))

    def test_arm32_public_preload_selection(self):
        raw=b"# original\nlibandroid.so\nlib32.so 32\nlib64.so 64\nlibskip.so nopreload\nlibskip32.so 32 nopreload\nlibandroid.so\n"
        self.assertEqual(vm.preload_names(raw),["libandroid.so","lib32.so"])
        for invalid in (b"",b"liba.so 32 64",b"../liba.so",b"liba.so unknown",b"liba.so nopreload nopreload"):
            with self.subTest(invalid=invalid),self.assertRaises(ValueError):
                vm.preload_names(invalid)

    def test_original_public_libraries_staging(self):
        raw=b"# original fixture\nlibc.so\nliblog.so\n"
        sources={"system":("debugfs","image","scratch")}
        with tempfile.TemporaryDirectory() as tmp:
            guest=Path(tmp)
            with patch.object(vm,"ext4_member",return_value=raw) as read:
                report=vm.stage_public_libraries(sources,guest)
                read.assert_called_once_with("debugfs","image",vm.PUBLIC_LIBRARIES,vm.MAX_PUBLIC_LIBRARIES,"scratch")
            target=guest/vm.PUBLIC_LIBRARIES.lstrip("/")
            self.assertEqual(target.read_bytes(),raw)
            self.assertEqual(target.stat().st_mode & 0o777,0o444)
            self.assertEqual(report["sha256"],vm.sha(raw))
            self.assertEqual(report["bytes"],len(raw))
            with patch.object(vm,"ext4_member",return_value=raw),self.assertRaises(FileExistsError):
                vm.stage_public_libraries(sources,guest)
            target.unlink()
            for invalid in (None,b"",b"x\0y",b"x"*(vm.MAX_PUBLIC_LIBRARIES+1)):
                with patch.object(vm,"ext4_member",return_value=invalid),self.assertRaises(ValueError):
                    vm.stage_public_libraries(sources,guest)
                self.assertFalse(target.exists())

    def test_vm_arguments_and_controls(self):
        cp=[ART_ROOT+"/javalib/"+n for n in BOOT_JARS]
        args=vm.vm_arguments(cp,fixture.CLASS)
        self.assertIn("-Xint",args)
        self.assertIn("-Ximage:/data/boot.art",args)
        self.assertEqual(args[-1],fixture.CLASS)
        with self.assertRaises(ValueError):
            vm.vm_arguments(cp[::-1],fixture.CLASS)
        with self.assertRaises(ValueError):
            vm.vm_arguments(cp,"OtherClass")
        evaluate=lambda name,rc,out,err:art.evaluate_case(name,rc,out,err,[],False,False,{})[0]
        self.assertEqual(evaluate("vm-java",0,fixture.MARKER+"\n",""),"JAVA_MARKER_PASS")
        self.assertEqual(evaluate("vm-java",1,fixture.MARKER+"\n",""),"REVIEW_REQUIRED")
        self.assertEqual(evaluate("vm-java",0,"",fixture.MARKER),"REVIEW_REQUIRED")
        self.assertEqual(evaluate("vm-java",0,fixture.MARKER+"\n","SIGSEGV"),"REVIEW_REQUIRED")
        self.assertEqual(evaluate("vm-missing-class",1,"","ClassNotFoundException: "+fixture.MISSING_CLASS),
                         "MISSING_CLASS_CONTROL_PASS")
        self.assertEqual(evaluate("vm-missing-class",1,"","failed"),"REVIEW_REQUIRED")
        self.assertEqual(art.guest_path(art.VM),ART_ROOT+"/bin/dalvikvm32")

if __name__=="__main__":
    unittest.main()
