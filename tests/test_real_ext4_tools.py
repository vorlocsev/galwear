"""Actual host EXT4 and SELinux lookup smoke; no mount, QEMU or AOSP.

Writes only a new synthetic temporary image using debugfs, then uses
the production read-only inspector. This is not e2fsdroid acceptance.
"""
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/"build"))
import r800_android_system_ext4 as a

REQUIRED = ("mke2fs","e2fsck","debugfs","matchpathcon")
LABEL = "u:object_r:init_exec:s0"

@unittest.skipUnless(all(shutil.which(x) for x in REQUIRED), "host EXT4/SELinux tools unavailable")
class RealExt4ToolsTests(unittest.TestCase):
    def test_matchpathcon_uses_inode_type(self):
        with tempfile.TemporaryDirectory(prefix="galwear-host-fc-",dir="/tmp") as tmp:
            fc = Path(tmp)/"file_contexts"
            fc.write_text("/system/bin/init -- u:object_r:init_exec:s0\n"
                          "/system/bin/init -l u:object_r:system_file:s0\n")
            self.assertEqual(a.expected_label(fc,"system/bin/init",0o100755,"matchpathcon"),LABEL)
            self.assertEqual(a.expected_label(fc,"system/bin/init",0o120777,"matchpathcon"),
                             "u:object_r:system_file:s0")

    def test_real_xattr_and_inode_metadata(self):
        with tempfile.TemporaryDirectory(prefix="galwear-host-ext4-",dir="/tmp") as tmp:
            root=Path(tmp)
            image=root/"fixture.ext4"
            with image.open("xb") as stream:
                stream.truncate(16*1024*1024)
            a.invoke(["mke2fs","-F","-t","ext4","-b","4096","-I","256","-m","0",
                      "-O","none,extent,filetype,dir_index,ext_attr,sparse_super,large_file",image])
            payload=root/"source"
            payload.write_bytes(b"synthetic diagnostic payload")
            label=root/"source-label"
            label.write_bytes(LABEL.encode()+b"\0")
            def write(command):
                a.invoke(["debugfs","-w","-R",command,image])
            write("mkdir /bin")
            write(f"write {payload} /bin/init")
            write("set_inode_field /bin/init mode 0100755")
            write("set_inode_field /bin/init uid 0")
            write("set_inode_field /bin/init gid 0")
            write(f"ea_set -f {label} /bin/init security.selinux")
            a.invoke(["e2fsck","-f","-n",image])
            item=(0o100755,payload.read_bytes(),0,0)
            before=a.sha(image.read_bytes())
            evidence=a.inspect_inode(image,"system/bin/init",item,LABEL,root,"debugfs")
            self.assertEqual(evidence["sha256"],a.sha(payload.read_bytes()))
            self.assertEqual(evidence["uid"],0)
            self.assertEqual(evidence["gid"],0)
            self.assertFalse(evidence["file_capabilities_present"])
            self.assertEqual(a.sha(image.read_bytes()),before)
            with self.assertRaisesRegex(ValueError,"xattr mismatch"):
                a.inspect_inode(image,"system/bin/init",item,"u:object_r:system_file:s0",root,"debugfs")
            write("set_inode_field /bin/init mode 0100644")
            with self.assertRaisesRegex(ValueError,"inode mode"):
                a.inspect_inode(image,"system/bin/init",item,LABEL,root,"debugfs")
            write("set_inode_field /bin/init mode 0100755")
            write("set_inode_field /bin/init uid 1000")
            with self.assertRaisesRegex(ValueError,"ownership"):
                a.inspect_inode(image,"system/bin/init",item,LABEL,root,"debugfs")

if __name__=="__main__":
    unittest.main()
