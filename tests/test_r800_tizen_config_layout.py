"""Real EXT4 configuration extraction and explicit chroot layout tests."""
import hashlib
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"build"))
import r800_tizen_config_layout as cfg


class TizenConfigLayoutTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root=Path(tmp.name)
        self.image=self.root/"rootfs.img"
        self.data={
            "/etc/lhd/lhd.conf":b"fixture=true\n",
            "/etc/gps-manager/brcm/gpsd.xml":b"<fixture/>\n",
            "/etc/passwd":b"root:x:0:0:root:/root:/bin/sh\nlocation:x:5000:5000::/opt/gnss:/bin/false\n",
            "/etc/group":b"root:x:0:\nlocation:x:5000:\n",
        }

    def fixture(self):
        tree=self.root/"source"
        tree.mkdir()
        for name,raw in self.data.items():
            dest=tree/name.lstrip("/")
            dest.parent.mkdir(parents=True,exist_ok=True)
            dest.write_bytes(raw)
        subprocess.run(["mke2fs","-q","-F","-t","ext4","-d",str(tree),str(self.image),"8192"],
                       check=True,capture_output=True)
        self.pin=hashlib.sha256(self.image.read_bytes()).hexdigest()

    def test_extract_real_ext4(self):
        self.fixture()
        data,identity=cfg.extract_configs(self.image,self.pin,self.root)
        self.assertEqual(data,self.data)
        self.assertEqual(identity["location_uid"],5000)
        self.assertFalse(identity["daemon_config_semantics_verified"])
        self.assertEqual(hashlib.sha256(self.image.read_bytes()).hexdigest(),self.pin)

    def test_secret_rejected(self):
        self.data["/etc/passwd"]=self.data["/etc/passwd"].replace(b"location:x:",b"location:$6$fixture:")
        self.fixture()
        with self.assertRaisesRegex(ValueError,"secret-bearing"):
            cfg.extract_configs(self.image,self.pin,self.root)

    def test_location_gid_mismatch(self):
        self.data["/etc/group"]=self.data["/etc/group"].replace(b"5000",b"5001")
        with self.assertRaisesRegex(ValueError,"identity mismatch"):
            cfg.inspect_config(self.data)

    def test_missing_config(self):
        del self.data["/etc/lhd/lhd.conf"]
        self.fixture()
        with self.assertRaises(ValueError):
            cfg.extract_configs(self.image,self.pin,self.root)

    def test_layout_binding(self):
        rows={cfg.PREFIX+p:{"mode":"0o644","bytes":len(raw)} for p,raw in self.data.items()}
        self.assertEqual(cfg.layout({"chroot_mountpoints":cfg.MOUNTPOINTS},rows),cfg.MOUNTPOINTS)
        with self.assertRaisesRegex(ValueError,"Incomplete"):
            cfg.layout({},rows)
        cfg.materialize(self.root,cfg.MOUNTPOINTS)
        for path in cfg.MOUNTPOINTS:
            cfg.verify_dir(self.root/path,path,cfg.MOUNTPOINTS)
            self.assertTrue((self.root/path).is_dir())

    def test_wrong_mountpoint_mode(self):
        cfg.materialize(self.root,cfg.MOUNTPOINTS)
        path=cfg.PREFIX+"/dev"
        (self.root/path).chmod(0o777)
        with self.assertRaisesRegex(ValueError,"mode mismatch"):
            cfg.verify_dir(self.root/path,path,cfg.MOUNTPOINTS)


if __name__=="__main__":
    unittest.main()
