"""Diagnostic boot stage contracts; fixture Image is not a compiled kernel."""
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"build"))
import r800_stage_boot_layer as stage
from test_r800_boot_candidate import dtb, kernel
from test_cpio_audit import make_newc
from test_initramfs_recipe import fake_aarch64_elf
from test_storage_isolation import CONFIG
from r800_storage_isolation import prepare


class BootLayerTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root=Path(tmp.name)
        self.out=self.root/"result"
        init=fake_aarch64_elf()
        archive=make_newc([("dev",0o040755,b""),("dev/console",0o020600,b""),
            ("proc",0o040555,b""),("sys",0o040555,b""),("data",0o040755,b""),
            ("init",0o100755,init)])
        self.blobs={"Image":kernel()+archive,"r800.dtb":dtb(),".config":prepare(CONFIG).encode(),
                    "init":init,"initramfs.cpio":archive}

    def run_stage(self,bad_pin=False):
        inputs={}
        for name,data in self.blobs.items():
            p=self.root/name
            p.write_bytes(data)
            inputs[name]=p
        pins={name:stage.sha(data) for name,data in self.blobs.items()}
        if bad_pin:
            pins["Image"]="0"*64
        with patch.object(stage,"checkout_sha"):
            return stage.stage(inputs,pins,self.out,"a"*40)

    def test_diagnostic_stage(self):
        report=self.run_stage()
        self.assertEqual(report["status"],"DIAGNOSTIC_BOOT_LAYER_STAGED_ONLY")
        self.assertEqual(report["exact_cpio_byte_offset"],64)
        self.assertIn("CONFIG_BLK_DEV_LOOP",report["android_handover_blockers"])
        self.assertIn("CONFIG_MMC",report["android_handover_blockers"])
        self.assertFalse(report["android_handover_supported"])
        self.assertFalse(report["kernel_initramfs_symbols_verified"])
        self.assertFalse(report["safe_to_flash"])
        self.assertEqual((self.out/"diagnostic-boot/Image").read_bytes(),self.blobs["Image"])

    def test_wrong_pin(self):
        with self.assertRaisesRegex(ValueError,"pin mismatch"):
            self.run_stage(bad_pin=True)
        self.assertFalse(self.out.exists())

    def test_detached_archive(self):
        self.blobs["Image"]=kernel()
        with self.assertRaisesRegex(ValueError,"exact CPIO byte occurrence"):
            self.run_stage()

    def test_duplicate_archive(self):
        self.blobs["Image"]+=self.blobs["initramfs.cpio"]
        with self.assertRaisesRegex(ValueError,"exact CPIO byte occurrence"):
            self.run_stage()

    def test_storage_enabled(self):
        self.blobs[".config"]=CONFIG.encode()
        with self.assertRaisesRegex(ValueError,"still enabled"):
            self.run_stage()

    def test_wrong_dtb(self):
        self.blobs["r800.dtb"]=dtb(b"OTHER\0")
        with self.assertRaisesRegex(ValueError,"model or SoC"):
            self.run_stage()

    def test_wrong_init(self):
        self.blobs["init"]+=b"changed"
        with self.assertRaisesRegex(ValueError,"differs"):
            self.run_stage()


if __name__=="__main__":
    unittest.main()
