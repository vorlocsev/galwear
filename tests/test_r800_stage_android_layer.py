"""Actual EXT4 image staging with synthetic ELF headers, not a working Android."""
import hashlib
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "build"))
import r800_stage_android_layer as layer


class AndroidLayerTests(unittest.TestCase):
    source = "a"*40

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.system = self.root/"system.img"
        self.vendor = self.root/"vendor.img"
        self.out = self.root/"output"

    def fixture(self, sdk="30", omit=None, bad_abi=False, init_target="/system/bin/init"):
        for name, image, dirs, files in (
                ("system", self.system, layer.SYSTEM_DIRS, layer.SYSTEM_FILES+("/system/bin/init",)),
                ("vendor", self.vendor, layer.VENDOR_DIRS, layer.VENDOR_FILES)):
            tree = self.root/name
            tree.mkdir()
            for path in dirs:
                if path != omit:
                    (tree/path.lstrip("/")).mkdir(parents=True,exist_ok=True)
            for path in files:
                if path == omit:
                    continue
                target = tree/path.lstrip("/")
                target.parent.mkdir(parents=True,exist_ok=True)
                raw = bytearray(64)
                raw[:7] = b"\x7fELF\x01\x01\x01"
                machine = 62 if bad_abi and path.endswith("app_process32") else 40
                struct.pack_into("<HH",raw,16,3,machine)
                target.write_bytes(raw)
                target.chmod(0o755 if "/bin/" in path else 0o644)
            prop = tree/("system/build.prop" if name=="system" else "build.prop")
            prop.write_text("ro.build.version.sdk="+sdk+"\nro.build.version.release=11\n"
                            "ro.product.cpu.abilist=armeabi-v7a\n")
            if name == "system":
                (tree/"init").symlink_to(init_target)
            subprocess.run(["mke2fs","-q","-t","ext4","-F","-d",str(tree),str(image),"8192"],
                           check=True,capture_output=True)

    def stage(self, wrong_pin=False):
        s=hashlib.sha256(self.system.read_bytes()).hexdigest()
        v=hashlib.sha256(self.vendor.read_bytes()).hexdigest()
        with patch.object(layer,"checkout_sha",return_value=self.source):
            return layer.stage(self.system,"0"*64 if wrong_pin else s,self.vendor,v,self.out,self.source)

    def test_actual_ext4_pair(self):
        self.fixture()
        result=self.stage()
        self.assertEqual(result["status"],"PREPARED_ANDROID_EXT4_PAIR_STAGED_ONLY")
        self.assertEqual((self.out/"r800dev/android/system.img").read_bytes(),self.system.read_bytes())
        self.assertEqual((self.out/"r800-android/vendor.img").read_bytes(),self.vendor.read_bytes())
        self.assertEqual(result["inspection"]["system"]["members"]["/init"]["target"],"/system/bin/init")
        self.assertEqual(result["inspection"]["system"]["members"]["/system/bin/app_process32"]["abi"],"arm")
        for flag in ("wear_os_verified","filesystem_integrity_verified","payload_complete",
                     "android_handover_tested","hardware_tested","safe_to_flash"):
            self.assertIs(result[flag],False)
        self.assertFalse((self.out/"r800dev/android/BOOT_ANDROID").exists())

    def test_wrong_pin(self):
        self.fixture()
        with self.assertRaisesRegex(ValueError,"SHA-256 mismatch"):
            self.stage(wrong_pin=True)
        self.assertFalse(self.out.exists())

    def test_missing_mountpoint(self):
        self.fixture(omit="/oem")
        with self.assertRaisesRegex(ValueError,"Android member"):
            self.stage()

    def test_missing_vendor_bind_target(self):
        self.fixture(omit="/lib/libbt-vendor.so")
        with self.assertRaisesRegex(ValueError,"Android member"):
            self.stage()

    def test_wrong_sdk(self):
        self.fixture(sdk="29")
        with self.assertRaisesRegex(ValueError,"Android 11"):
            self.stage()

    def test_wrong_app_process_isa(self):
        self.fixture(bad_abi=True)
        with self.assertRaisesRegex(ValueError,"architecture or type"):
            self.stage()

    def test_unexpected_init_link(self):
        self.fixture(init_target="/system/bin/other")
        with self.assertRaisesRegex(ValueError,"init symlink"):
            self.stage()

    def test_existing_output(self):
        self.fixture()
        self.out.mkdir()
        with self.assertRaisesRegex(ValueError,"Fresh output"):
            self.stage()


if __name__=="__main__":
    unittest.main()
