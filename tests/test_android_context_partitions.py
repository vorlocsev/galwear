"""Synthetic context partition and APEX preservation contracts."""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"build"))
import r800_android_context_partitions as p
import r800_android_apex_payload as a

class PartitionTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root=Path(temp.name)

    def put(self,rel,data):
        path=self.root/rel
        path.parent.mkdir(parents=True,exist_ok=True)
        path.write_bytes(data)

    def test_partition_context_selection(self):
        prop="vendor/etc/selinux/vendor_property_contexts"
        fc="vendor/etc/selinux/vendor_file_contexts"
        self.put(prop,b"properties")
        self.put(fc,b"contexts")
        r=p.collect(self.root,{prop:p.sha(b"properties")})
        self.assertEqual(set(r),{"vendor"})
        self.assertEqual(set(r["vendor"]),{"vendor","vendor/etc","vendor/etc/selinux",prop,fc})

    def test_missing_file_contexts_rejected(self):
        prop="product/etc/selinux/product_property_contexts"
        self.put(prop,b"properties")
        with self.assertRaisesRegex(ValueError,"Missing required partition"):
            p.collect(self.root,{prop:p.sha(b"properties")})

    def test_property_context_mutation(self):
        prop="system_ext/etc/selinux/system_ext_property_contexts"
        self.put(prop,b"changed")
        self.put("system_ext/etc/selinux/system_ext_file_contexts",b"contexts")
        with self.assertRaisesRegex(ValueError,"identity mismatch"):
            p.collect(self.root,{prop:p.sha(b"original")})

    def test_absent_optional_partitions(self):
        self.assertEqual(p.collect(self.root,{}),{})

    def test_apex_label_readback(self):
        def fake(args):
            self.assertIn("ea_get -f",args[2])
            (self.root/"label").write_bytes(b"u:object_r:system_file:s0\0")
            return subprocess.CompletedProcess(args,0)
        with patch.object(a,"invoke",side_effect=fake):
            self.assertEqual(a.read_label("image","/bin/linker64",self.root,"debugfs"),
                             "u:object_r:system_file:s0")

    def test_invalid_apex_label(self):
        def fake(args):
            (self.root/"label").write_bytes(b"invalid\0")
        with patch.object(a,"invoke",side_effect=fake):
            with self.assertRaisesRegex(ValueError,"Invalid APEX"):
                a.read_label("image","/bin/linker64",self.root,"debugfs")

    def test_apex_traversal_rejected(self):
        with patch.object(a,"invoke") as run:
            with self.assertRaisesRegex(ValueError,"Unexpected APEX"):
                a.read_label("image","/../host",self.root,"debugfs")
            run.assert_not_called()

    def test_apex_staged_mismatch(self):
        self.put(a.RUNTIME+"/"+a.FILES[0],b"staged")
        with patch.object(a,"read_label",return_value="u:object_r:system_file:s0"), \
             patch.object(a,"dump_file"), \
             patch.object(a,"inspect_elf",return_value={"sha256":a.sha(b"original")}):
            with self.assertRaisesRegex(ValueError,"differs from original"):
                a.verify_selected("image",self.root,self.root,"debugfs","readelf")

if __name__=="__main__":
    unittest.main()
