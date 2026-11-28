"""Synthetic export inventory fixtures, never import or boot a VM."""
import hashlib
from pathlib import Path
import tempfile
import unittest
import sys

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"build"))
import r800_vm_export_lock as vm

SOURCE="a"*40
PIN="b"*64


class VmExportLockTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root=Path(tmp.name)
        self.export=self.root/"export"
        self.export.mkdir()
        self.ova=self.export/"baseline.ova"
        self.ova.write_bytes(b"opaque fixture")
        self.decl={"schema":"galwear-r800-vm-export-declaration-v1","source_sha":SOURCE,
                   "profile_sha256":PIN,"package_lock_sha256":PIN,"iso_sha256":"c"*64,
                   "hypervisor":"fixture","hypervisor_version":"1","snapshot_id":"baseline",
                   **{n:True for n in ("powered_off","donor_free","physical_passthrough_disabled",
                        "shared_host_folders_disabled","network_disconnected")}}

    def test_opaque_ova(self):
        report=vm.inventory(self.export)
        self.assertEqual(report["format"],"OPAQUE_OVA")
        self.assertEqual(report["files"]["baseline.ova"]["sha256"],
                         hashlib.sha256(b"opaque fixture").hexdigest())

    def test_modified_bytes(self):
        before=vm.inventory(self.export)
        self.ova.write_bytes(b"changed")
        self.assertNotEqual(before,vm.inventory(self.export))

    def test_flat_ovf(self):
        self.ova.unlink()
        (self.export/"baseline.ovf").write_bytes(b"fixture descriptor")
        (self.export/"disk.vmdk").write_bytes(b"fixture disk")
        self.assertEqual(vm.inventory(self.export)["format"],"OPAQUE_OVF_VMDK_SET")

    def test_unexpected_file(self):
        (self.export/"extra.txt").write_text("extra")
        with self.assertRaisesRegex(ValueError,"Expected one OVA"):
            vm.inventory(self.export)

    def test_symlink_rejected(self):
        (self.export/"alias.vmdk").symlink_to(self.ova)
        with self.assertRaisesRegex(ValueError,"regular nonlinked"):
            vm.inventory(self.export)

    def test_directory_rejected(self):
        (self.export/"extra").mkdir()
        with self.assertRaisesRegex(ValueError,"regular nonlinked"):
            vm.inventory(self.export)

    def test_empty_file_rejected(self):
        self.ova.write_bytes(b"")
        with self.assertRaisesRegex(ValueError,"byte budget"):
            vm.inventory(self.export)

    def test_declaration(self):
        vm.metadata(self.decl,SOURCE,PIN,PIN)

    def test_declaration_wrong_head(self):
        with self.assertRaisesRegex(ValueError,"declaration or binding"):
            vm.metadata(self.decl,"0"*40,PIN,PIN)

    def test_declaration_not_powered_off(self):
        self.decl["powered_off"]=False
        with self.assertRaisesRegex(ValueError,"safety declaration"):
            vm.metadata(self.decl,SOURCE,PIN,PIN)


if __name__=="__main__":
    unittest.main()
