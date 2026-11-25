"""Synthetic selected-inventory linker resolution contracts."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"build"))
import r800_ext4_linker_resolution as a

def fixture():
    def elf(digest,needed=(),soname=None,interp=None):
        return {"sha256":digest*64,"elf_type":3,"needed":list(needed),
                "soname":soname,"interpreter":interp}
    entries={"system/etc/ld.config.txt":{"sha256":a.sha(a.CONFIG)},
             a.LINK:{"type":"symlink","target":"../../apex/com.android.runtime/bin/linker64"}}
    staged={}
    selected={}
    for root in a.ROOTS:
        info=elf("a",["libc.so"],interp="/"+a.LINK)
        staged[root]=info
        entries[root]={"type":"regular","sha256":info["sha256"]}
    labels={}
    for i,name in enumerate(a.LIBS):
        path="/lib64/bionic/"+name
        info=elf(str(i+1),soname=name)
        labels[path]={"elf":info,"sha256":info["sha256"]}
    linker=elf("b")
    labels["/bin/linker64"]={"elf":linker,"sha256":linker["sha256"]}
    staged[a.RUNTIME+"/bin/linker64"]=linker
    libc=a.RUNTIME+"/lib64/bionic/libc.so"
    staged[libc]=labels["/lib64/bionic/libc.so"]["elf"]
    selected["libc.so"]="runtime:"+libc
    return ({"policy_sha256":"c"*64,"image_sha256":"d"*64,
             "verified_system_entries":entries,"staged_elf_metadata":staged,
             "selected_libraries":selected,"service_fixture":True,
             "experimental_linker_config_sha256":a.sha(a.CONFIG)},
            {"policy_sha256":"c"*64,"payload_sha256":"e"*64,"selected_inode_labels":labels})

class LinkerTests(unittest.TestCase):
    def test_runtime_interpreter_and_dependency(self):
        result=a.evaluate(*fixture())
        self.assertEqual(result["status"],a.STATUS)
        self.assertFalse(result["namespace_resolution_tested"])
        self.assertFalse(result["symbol_relocations_tested"])
        for info in result["executables"].values():
            self.assertEqual(info["interpreter"],"/"+a.RUNTIME+"/bin/linker64")
            self.assertEqual(info["edges"][0]["resolved"],"/"+a.RUNTIME+"/lib64/bionic/libc.so")

    def test_system_shadow_rejected(self):
        s,r=fixture()
        path="system/lib64/bootstrap/libc.so"
        info=dict(s["staged_elf_metadata"][a.RUNTIME+"/lib64/bionic/libc.so"],sha256="f"*64)
        s["staged_elf_metadata"][path]=info
        s["verified_system_entries"][path]={"type":"regular","sha256":info["sha256"]}
        with self.assertRaisesRegex(ValueError,"Search order"):
            a.evaluate(s,r)

    def test_wrong_alias_rejected(self):
        s,r=fixture()
        s["verified_system_entries"][a.LINK]["target"]="/etc/passwd"
        with self.assertRaisesRegex(ValueError,"Unexpected linker alias"):
            a.evaluate(s,r)

    def test_apex_digest_mismatch(self):
        s,r=fixture()
        r["selected_inode_labels"]["/bin/linker64"]["sha256"]="0"*64
        with self.assertRaisesRegex(ValueError,"APEX ELF digest mismatch"):
            a.evaluate(s,r)

    def test_system_digest_mismatch(self):
        s,r=fixture()
        s["verified_system_entries"][a.ROOTS[0]]["sha256"]="0"*64
        with self.assertRaisesRegex(ValueError,"System ELF digest mismatch"):
            a.evaluate(s,r)

    def test_unselected_dependency_rejected(self):
        s,r=fixture()
        s["selected_libraries"].clear()
        with self.assertRaisesRegex(ValueError,"Missing explicit dependency"):
            a.evaluate(s,r)

    def test_policy_identity_mismatch(self):
        s,r=fixture()
        r["policy_sha256"]="0"*64
        with self.assertRaisesRegex(ValueError,"Different image policy"):
            a.evaluate(s,r)

    def test_wrong_config_rejected(self):
        s,r=fixture()
        s["experimental_linker_config_sha256"]="0"*64
        with self.assertRaisesRegex(ValueError,"Unexpected experimental linker config"):
            a.evaluate(s,r)

if __name__=="__main__":
    unittest.main()
