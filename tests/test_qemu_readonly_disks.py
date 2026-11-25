"""Synthetic virt disk acceptance tests; no QEMU execution."""
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"build"))
import r800_qemu_readonly_disks as a

DISKS=[{"name":"system","path":Path("/tmp/system.ext4"),"manifest_slot":"vda"},
       {"name":"runtime","path":Path("/tmp/runtime.ext4"),"manifest_slot":"vdb"}]
LOG=(a.EXPECTED+b"r800-virt-disk: system serial=PASS block-ro=1 ext4-ro=1\n"
     b"r800-virt-disk: runtime serial=PASS block-ro=1 ext4-ro=1\n"
     b"r800-virt-disk: PASS count=2 policy=not-loaded android=not-started\n"
     +a.HEARTBEAT_PREFIX+b"00000001\n")

class ReadOnlyDiskTests(unittest.TestCase):
    def test_command_only_readonly_raw(self):
        args=a.command(Path("Image"),Path("initrd"),DISKS)
        self.assertNotIn("-drive",args)
        self.assertEqual(args[args.index("-nic")+1],"none")
        for i in [i for i,x in enumerate(args) if x=="-blockdev"]:
            block=json.loads(args[i+1])
            self.assertEqual(block["driver"],"raw")
            self.assertIs(block["read-only"],True)
            self.assertIs(block["file"]["read-only"],True)
        self.assertEqual(args.count("-blockdev"),2)

    def test_exact_mount_evidence(self):
        r=a.inspect_console(LOG,DISKS)
        self.assertEqual(r["mounted_disk_count"],2)
        self.assertFalse(r["selinux_policy_loaded"])
        self.assertFalse(r["guest_selinux_labels_verified"])

    def test_rw_or_wrong_serial_rejected(self):
        for old,new in ((b"block-ro=1",b"block-ro=0"),(b"ext4-ro=1",b"ext4-ro=0"),
                        (b"serial=PASS",b"serial=FAIL")):
            with self.assertRaisesRegex(ValueError,"diagnostics"):
                a.inspect_console(LOG.replace(old,new),DISKS)

    def test_duplicate_disk_rejected(self):
        line=LOG.splitlines()[1]
        with self.assertRaisesRegex(ValueError,"diagnostics"):
            a.inspect_console(LOG.replace(line,line+b"\n"+line),DISKS)

    def test_early_heartbeat_rejected(self):
        with self.assertRaisesRegex(ValueError,"Heartbeat before"):
            a.inspect_console(LOG.replace(b"r800-virt-disk: PASS",a.HEARTBEAT_PREFIX+b"00000001\nr800-virt-disk: PASS"),DISKS)

    def test_archive_manifest(self):
        data=a.disk_archive(b"binary",DISKS)
        self.assertIn(b"system vda\nruntime vdb\n",data)
        self.assertNotIn(b"system.ext4",data)

    def test_image_symlink_and_digest_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/"system.ext4"
            p.write_bytes(b"fake")
            link=p.with_name("link")
            link.symlink_to(p)
            with self.assertRaisesRegex(ValueError,"non-symlink"):
                a.verify_image(link,"system","a"*64,4)
            with self.assertRaisesRegex(ValueError,"identity mismatch"):
                a.verify_image(p,"system","a"*64,4)

if __name__=="__main__":
    unittest.main()
