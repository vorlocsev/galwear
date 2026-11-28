"""Small synthetic OVF/VMDK/OVA fixtures; no VM import or execution."""
import io
from pathlib import Path
import struct
import sys
import tarfile
import tempfile
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"build"))
import r800_vm_export_structure as vm


def disk(name="disk.vmdk",parent="ffffffff",extent=None):
    text=f'''# Disk DescriptorFile
version=1
CID=01234567
parentCID={parent}
createType="streamOptimized"
RW 2048 SPARSE "{extent or name}"
'''.encode()
    header=bytearray(512)
    header[:4]=b"KDMV"
    struct.pack_into("<IIQQQQ",header,4,3,0x10000,2048,128,1,1)
    return bytes(header)+text.ljust(512,b"\0")


def xml(href="disk.vmdk",ref="f1",size=1024):
    return f'''<Envelope xmlns="{vm.OVF}" xmlns:ovf="{vm.OVF}">
<References><File ovf:id="f1" ovf:href="{href}" ovf:size="{size}"/></References>
<DiskSection><Disk ovf:diskId="d1" ovf:fileRef="{ref}"/></DiskSection>
<VirtualSystem ovf:id="fixture"/>
</Envelope>'''.encode()


class StructureTests(unittest.TestCase):
    def setUp(self):
        self.data={"baseline.ovf":xml(),"disk.vmdk":disk()}
        tmp=tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root=Path(tmp.name)

    def examine(self):
        return vm.examine({n:len(b) for n,b in self.data.items()},
                          lambda n,o,c:self.data[n][o:o+c])

    def test_self_contained(self):
        result=self.examine()
        self.assertEqual(result["disks"],{"d1":"disk.vmdk"})
        self.assertEqual(result["vmdk_descriptors"]["disk.vmdk"]["capacity_sectors"],2048)

    def test_parent_disk(self):
        self.data["disk.vmdk"]=disk(parent="01234567")
        with self.assertRaisesRegex(ValueError,"parent or unsupported"):
            self.examine()

    def test_external_extent(self):
        self.data["disk.vmdk"]=disk(extent="other.vmdk")
        with self.assertRaisesRegex(ValueError,"External or invalid"):
            self.examine()

    def test_unsafe_href(self):
        self.data["baseline.ovf"]=xml(href="../disk.vmdk")
        with self.assertRaisesRegex(ValueError,"Unsafe or non-flat"):
            self.examine()

    def test_external_url(self):
        self.data["baseline.ovf"]=xml(href="https://example.org/disk.vmdk")
        with self.assertRaisesRegex(ValueError,"Unsafe or non-flat"):
            self.examine()

    def test_unknown_ref(self):
        self.data["baseline.ovf"]=xml(ref="missing")
        with self.assertRaisesRegex(ValueError,"disk reference"):
            self.examine()

    def test_unreferenced_disk(self):
        self.data["extra.vmdk"]=disk("extra.vmdk")
        with self.assertRaisesRegex(ValueError,"Unreferenced"):
            self.examine()

    def test_size_mismatch(self):
        self.data["baseline.ovf"]=xml(size=512)
        with self.assertRaisesRegex(ValueError,"size mismatch"):
            self.examine()

    def test_doctype(self):
        self.data["baseline.ovf"]=b"<!DOCTYPE Envelope>"+xml()
        with self.assertRaisesRegex(ValueError,"encoding or declaration"):
            self.examine()

    def test_descriptor_bounds(self):
        b=bytearray(self.data["disk.vmdk"])
        struct.pack_into("<Q",b,28,999)
        self.data["disk.vmdk"]=bytes(b)
        with self.assertRaisesRegex(ValueError,"descriptor bounds"):
            self.examine()

    def archive(self,extra=None):
        path=self.root/"fixture.ova"
        with tarfile.open(path,"w",format=tarfile.USTAR_FORMAT) as tar:
            for name,data in self.data.items():
                item=tarfile.TarInfo(name)
                item.size=len(data)
                tar.addfile(item,io.BytesIO(data))
            if extra is not None:
                tar.addfile(extra,io.BytesIO(b"x"*extra.size))
        return {"format":"OPAQUE_OVA","files":{"fixture.ova":{"bytes":path.stat().st_size}}}

    def test_ova(self):
        self.assertEqual(vm.structural(self.root,self.archive())["disks"],{"d1":"disk.vmdk"})

    def test_ova_symlink(self):
        item=tarfile.TarInfo("alias.vmdk")
        item.type=tarfile.SYMTYPE
        item.linkname="disk.vmdk"
        with self.assertRaisesRegex(ValueError,"Unsupported or duplicate"):
            vm.structural(self.root,self.archive(item))

    def test_ova_duplicate(self):
        item=tarfile.TarInfo("disk.vmdk")
        item.size=1
        with self.assertRaisesRegex(ValueError,"Unsupported or duplicate"):
            vm.structural(self.root,self.archive(item))


if __name__=="__main__":
    unittest.main()
