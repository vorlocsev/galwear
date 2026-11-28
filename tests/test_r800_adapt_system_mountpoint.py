"""Rootless adaptation of real EXT4 fixtures with synthetic Android ELF headers."""
import hashlib
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"build"))
import r800_adapt_system_mountpoint as adapt


class SystemMountpointTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root=Path(tmp.name)
        self.image=self.root/"system.img"
        self.output=self.root/"prepared"

    def fixture(self,oem=None,omit=None,sdk="30",trailer=False):
        root=self.root/"tree"
        root.mkdir()
        for path in adapt.SYSTEM_DIRS:
            if path not in ("/oem",omit):
                (root/path.lstrip("/")).mkdir(parents=True,exist_ok=True)
        for path in adapt.SYSTEM_FILES+("/system/bin/init",):
            if path==omit:
                continue
            p=root/path.lstrip("/")
            p.parent.mkdir(parents=True,exist_ok=True)
            data=bytearray(64)
            data[:7]=b"\x7fELF\x01\x01\x01"
            struct.pack_into("<HH",data,16,3,40)
            p.write_bytes(data)
            p.chmod(0o755)
        (root/"init").symlink_to("/system/bin/init")
        (root/"system/build.prop").write_text("ro.build.version.sdk="+sdk+"\nro.build.version.release=11\nro.product.cpu.abi=armeabi-v7a\n")
        (root/"system/etc/prop.default").write_text("ro.secure=1\n")
        if oem=="directory":
            (root/"oem").mkdir()
        elif oem=="symlink":
            (root/"oem").symlink_to("/vendor")
        subprocess.run(["mke2fs","-q","-F","-t","ext4","-b","4096","-d",str(root),str(self.image),"2048"],
                       check=True,capture_output=True)
        if trailer:
            with self.image.open("ab") as stream:
                stream.write(b"AVBf"+bytes(4092))
        self.original=self.image.read_bytes()
        self.pin=hashlib.sha256(self.original).hexdigest()

    def prepare(self,pin=None):
        with patch.object(adapt,"checkout_sha"):
            return adapt.prepare(self.image,pin or self.pin,self.output,"a"*40)

    def test_create_mountpoint(self):
        self.fixture()
        result=self.prepare()
        self.assertTrue(result["added_oem"])
        self.assertEqual(result["oem_mountpoint"],{"type":"directory","mode":"0o755"})
        self.assertTrue(result["selected_original_members_unchanged"])
        self.assertNotEqual(result["original"]["sha256"],result["system"]["sha256"])
        self.assertEqual(self.image.read_bytes(),self.original)
        self.assertFalse(result["selinux_label_compatibility_verified"])
        self.assertFalse(result["safe_to_flash"])

    def test_existing_directory_unchanged(self):
        self.fixture(oem="directory")
        result=self.prepare()
        self.assertFalse(result["added_oem"])
        self.assertEqual((self.output/"system.img").read_bytes(),self.original)

    def test_symlink_not_replaced(self):
        self.fixture(oem="symlink")
        with self.assertRaisesRegex(ValueError,"not a directory"):
            self.prepare()
        self.assertFalse(self.output.exists())

    def test_missing_zygote(self):
        self.fixture(omit="/system/bin/app_process32")
        with self.assertRaisesRegex(ValueError,"Android member"):
            self.prepare()

    def test_incompatible_sdk(self):
        self.fixture(sdk="29")
        with self.assertRaisesRegex(ValueError,"Android 11"):
            self.prepare()

    def test_trailing_data_not_modified(self):
        self.fixture(trailer=True)
        with self.assertRaisesRegex(ValueError,"Trailing partition data"):
            self.prepare()
        self.assertEqual(self.image.read_bytes(),self.original)

    def test_wrong_pin(self):
        self.fixture()
        with self.assertRaisesRegex(ValueError,"SHA-256 mismatch"):
            self.prepare("0"*64)


if __name__=="__main__":
    unittest.main()
