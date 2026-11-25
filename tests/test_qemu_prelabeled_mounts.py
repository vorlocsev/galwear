"""Synthetic pre-labeled mount contracts, not actual guest evidence."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"build"))
import r800_qemu_prelabeled_mounts as a

D=[{"name":"system","sha256":"a"*64,"bytes":128,"manifest_slot":"vda"},
   {"name":"runtime","sha256":"b"*64,"bytes":128,"manifest_slot":"vdb"}]
L={"/system/bin/init":"u:object_r:init_exec:s0"}
LOG=(a.disks.PREFIX+b"PASS count=2 policy=not-loaded android=not-started\n"+
     a.START+b"\n"+a.PREFIX+b"path=/system/bin/init context=u:object_r:init_exec:s0\n"+
     a.PREFIX+b"PASS count=1 android=not-started\n"+a.HEARTBEAT_PREFIX+b"00000001\n")

def inventories():
    system={"verified_system_entries":{n:{"context":"u:object_r:system_file:s0"}
             for n in ("system","system/bin/galwear_property_service",
                       "system/bin/galwear_property_client","system/etc/selinux/plat_property_contexts")}}
    system["verified_system_entries"]["system/bin/init"]={"context":"u:object_r:init_exec:s0"}
    extra={"partitions":{}}
    runtime={"selected_inode_labels":{p:{"context":"u:object_r:system_file:s0"}
             for p in {"/","/bin","/lib64","/lib64/bionic"}|{"/"+f for f in a.FILES}}}
    return system,extra,runtime

class LabelMountTests(unittest.TestCase):
    def test_plan(self):
        plan=a.label_plan(*inventories())
        self.assertIn("/apex/com.android.runtime/bin/linker64",plan)
        self.assertEqual(plan["/system/bin/init"],"u:object_r:init_exec:s0")

    def test_outside_partition(self):
        s,e,r=inventories()
        s["verified_system_entries"]["dev/console"]={"context":"u:object_r:system_file:s0"}
        with self.assertRaisesRegex(ValueError,"Invalid or duplicate"):
            a.label_plan(s,e,r)

    def test_incomplete_apex(self):
        s,e,r=inventories()
        del r["selected_inode_labels"]["/bin"]
        with self.assertRaisesRegex(ValueError,"Incomplete runtime"):
            a.label_plan(s,e,r)

    def test_wrong_init_label(self):
        s,e,r=inventories()
        s["verified_system_entries"]["system/bin/init"]["context"]="u:object_r:system_file:s0"
        with self.assertRaisesRegex(ValueError,"init executable"):
            a.label_plan(s,e,r)

    def test_effective_label_contract(self):
        r=a.inspect_console(LOG,D,L)
        self.assertTrue(r["guest_selinux_labels_verified"])
        self.assertFalse(r["android_init_started"])
        self.assertFalse(r["apex_activation_tested"])

    def test_wrong_label_or_enforcing(self):
        for old,new in ((b"init_exec:s0",b"system_file:s0"),(b"enforce=1",b"enforce=0")):
            with self.assertRaisesRegex(ValueError,"effective label"):
                a.inspect_console(LOG.replace(old,new),D,L)

    def test_early_heartbeat(self):
        with self.assertRaisesRegex(ValueError,"Heartbeat before"):
            a.inspect_console(LOG.replace(a.START,a.HEARTBEAT_PREFIX+b"00000001\n"+a.START),D,L)

    def test_previous_control(self):
        prior={"status":"VIRT_ANDROID_READONLY_BLOCK_MOUNTS_ONLY",
               "generic_kernel_sha256":"kernel","config_sha256":"config","policy_sha256":"policy",
               "safe_to_flash":False,"disk_hashes_unchanged":True,"block_read_only_reported":True,
               "ext4_read_only_reported":True,"disk_serials_verified":True,
               "guest_progress_after_marker_verified":True,"selinux_policy_loaded":False,
               "mounted_disk_count":2,"disks":D}
        a.verify_previous(prior,"kernel","config","policy",D)
        with self.assertRaisesRegex(ValueError,"Matching successful"):
            a.verify_previous(prior,"kernel","config","policy",D[::-1])

if __name__=="__main__":
    unittest.main()
