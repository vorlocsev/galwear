"""Synthetic EXT4 transition tests; no guest execution."""
from pathlib import Path
import copy
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"build"))
import r800_qemu_ext4_init_transition as a

D=[{"name":"system"},{"name":"runtime"}]
L={"/system/bin/init":"u:object_r:init_exec:s0"}
CONSOLE = b" device=5:1 inode=42 filesystem=0:1\n"
LOG=(a.disks.EXPECTED+b"r800-console: stage=kernel"+CONSOLE+b"r800-ext4-exec: system noexec=0\nr800-ext4-exec: runtime noexec=1\n"+
     a.disks.PREFIX+b"PASS count=2 policy=not-loaded android=not-started\n"+
     a.labels.START+b"\n"+a.labels.PREFIX+b"path=/system/bin/init context=u:object_r:init_exec:s0\n"+
     a.labels.PREFIX+b"PASS count=1 android=not-started\n"+
     a.MARKERS[0]+b"\n"+b"r800-console: stage=init"+CONSOLE+
     b"\n".join(a.MARKERS[1:])+b"\n"+a.HEARTBEAT_PREFIX+b"00000001\n")

def images():
    old={"policy_sha256":"policy","platform_file_contexts_sha256":"contexts",
         "property_contexts_sha256":{},"image_bytes":128,"image_sha256":"old",
         "verified_system_entries":{
             a.TARGET:{"context":"u:object_r:init_exec:s0","sha256":"original","mode":"755","type":"regular"},
             "system/bin/galwear_property_client":{"context":"u:object_r:system_file:s0","sha256":"client"}}}
    new=copy.deepcopy(old)
    new["image_sha256"]="new"
    new["verified_system_entries"][a.TARGET]["sha256"]="diagnostic"
    new["diagnostic_init_substitution"]={"path":"/"+a.TARGET,"original_sha256":"original","diagnostic_sha256":"diagnostic"}
    return old,new

class Ext4TransitionTests(unittest.TestCase):
    def test_single_substitution(self):
        a.verify_substitution(*images(),"diagnostic")

    def test_other_inode_change_rejected(self):
        old,new=images()
        new["verified_system_entries"]["system/bin/galwear_property_client"]["sha256"]="changed"
        with self.assertRaisesRegex(ValueError,"Unexpected system inode"):
            a.verify_substitution(old,new,"diagnostic")

    def test_wrong_init_hash(self):
        with self.assertRaisesRegex(ValueError,"Unexpected system inode"):
            a.verify_substitution(*images(),"wrong")

    def test_wrong_policy(self):
        old,new=images()
        new["policy_sha256"]="changed"
        with self.assertRaisesRegex(ValueError,"metadata changed"):
            a.verify_substitution(old,new,"diagnostic")

    def test_success_is_diagnostic_only(self):
        r=a.inspect_console(LOG,D,L)
        self.assertTrue(r["init_domain_entered"])
        self.assertFalse(r["original_init_executed"])
        self.assertFalse(r["android_init_started"])

    def test_other_partition_exec_rejected(self):
        with self.assertRaisesRegex(ValueError,"execution flags"):
            a.inspect_console(LOG.replace(b"runtime noexec=1",b"runtime noexec=0"),D,L)

    def test_wrong_domain_rejected(self):
        with self.assertRaisesRegex(ValueError,"transition sequence"):
            a.inspect_console(LOG.replace(b"domain=u:r:init:s0",b"domain=u:r:kernel:s0"),D,L)

    def test_changed_console_rejected(self):
        with self.assertRaisesRegex(ValueError,"stdout identity changed"):
            a.inspect_console(LOG.replace(b"stage=init"+CONSOLE,
                b"stage=init"+CONSOLE.replace(b"inode=42",b"inode=43")),D,L)

    def test_early_heartbeat(self):
        with self.assertRaisesRegex(ValueError,"Heartbeat before diagnostic"):
            a.inspect_console(LOG.replace(a.MARKERS[-1],a.HEARTBEAT_PREFIX+b"00000001\n"+a.MARKERS[-1]),D,L)

if __name__=="__main__":
    unittest.main()
