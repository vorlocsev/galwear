"""Compose actual EXT4 fixtures and synthetic adaptation files, not real Wear OS."""
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"build"))
import r800_stage_development_tree as dev
import r800_stage_android_layer as android

SOURCE="a"*40


def elf():
    raw=bytearray(64)
    raw[:7]=b"\x7fELF\x01\x01\x01"
    struct.pack_into("<HH",raw,16,3,40)
    return bytes(raw)


def write(root,name,data,mode):
    path=root/name.lstrip("/")
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_bytes(data)
    path.chmod(mode)


class DevelopmentTreeTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root=Path(tmp.name)
        self.adaptation=self.root/"adaptation"
        self.adaptation.mkdir()
        self.android=self.root/"android"
        self.out=self.root/"result"

    def fixture(self, vendor_mismatch=False):
        rows={}
        modes={**dev.DEVICE,**{n:("0o755" if n=="r800dev/gpsbridge" or
            n.startswith("r800dev/tzlite/usr/bin/") or n.endswith("/ld-linux.so.3") else "0o644")
            for n in dev.RUNTIME_REQUIRED}}
        for name,mode in sorted(modes.items()):
            data=elf() if name.endswith(".so") else Path(name).name.encode()
            write(self.adaptation,name,data,int(mode,8))
            rows[name]={"bytes":len(data),"sha256":dev.sha(data),"mode":mode,
                        "layer":"device" if name in dev.DEVICE else "tizen-runtime"}
        report={"schema":"galwear-r800-adaptation-layer-v1",
                "status":"DEVICE_AND_LOCAL_TIZEN_ADAPTATION_STAGED_ONLY",
                "source_sha":SOURCE,"device_manifest_sha256":"b"*64,
                "runtime_manifest_sha256":"c"*64,"files":rows,
                "total_bytes":sum(r["bytes"] for r in rows.values())}
        report.update({f:False for f in ("donor_authenticity_verified","full_runtime_built",
            "complete_vendor_built","payload_complete","android_handover_tested","hardware_tested","safe_to_flash")})
        raw=json.dumps(report).encode()
        (self.adaptation/"adaptation-layer-evidence.json").write_bytes(raw)
        self.apin=dev.sha(raw)
        for partition,dirs,files in (("system",android.SYSTEM_DIRS,android.SYSTEM_FILES+("/system/bin/init",)),
                                      ("vendor",android.VENDOR_DIRS,android.VENDOR_FILES)):
            tree=self.root/(partition+"-root")
            tree.mkdir()
            for path in dirs:
                (tree/path.lstrip("/")).mkdir(parents=True,exist_ok=True)
            for path in files:
                write(tree,path,elf(),0o755 if "/bin/" in path else 0o644)
            if partition=="system":
                (tree/"init").symlink_to("/system/bin/init")
                prop="system/build.prop"
            else:
                prop="build.prop"
                for name,row in rows.items():
                    if name.startswith("vendor/"):
                        data=(self.adaptation/name).read_bytes()
                        if vendor_mismatch and name.endswith("hwcomposer.r800.so"):
                            data=data[:-1]+b"x"
                        write(tree,name.removeprefix("vendor/"),data,int(row["mode"],8))
            write(tree,prop,b"ro.build.version.sdk=30\nro.build.version.release=11\nro.product.cpu.abilist=armeabi-v7a\n",0o644)
            image=self.root/(partition+".img")
            subprocess.run(["mke2fs","-q","-t","ext4","-F","-d",str(tree),str(image),"8192"],
                           check=True,capture_output=True)
        s,v=self.root/"system.img",self.root/"vendor.img"
        with patch.object(android,"checkout_sha"):
            android.stage(s,dev.sha(s.read_bytes()),v,dev.sha(v.read_bytes()),self.android,SOURCE)
        self.bpin=dev.sha((self.android/"android-layer-evidence.json").read_bytes())

    def assemble(self):
        with patch.object(dev,"checkout_sha"):
            return dev.assemble(self.adaptation,self.apin,self.android,self.bpin,self.out,SOURCE)

    def test_actual_ext4_composition(self):
        self.fixture()
        result=self.assemble()
        self.assertEqual(result["status"],"ANDROID_DEVICE_DEVELOPMENT_TREE_STAGED_ONLY")
        self.assertEqual(len(result["vendor_overlay_matches"]),11)
        self.assertEqual(result["vendor_tree_role"],"BUILD_PROVENANCE_ONLY")
        self.assertFalse(result["safe_to_flash"])
        self.assertFalse((self.out/"r800dev/android/BOOT_ANDROID").exists())
        self.assertFalse((self.out/"r800dev/android/persistent.img").exists())
        self.assertEqual((self.out/"r800-android/vendor.img").read_bytes(),
                         (self.android/"r800-android/vendor.img").read_bytes())

    def test_stale_vendor_hal(self):
        self.fixture(vendor_mismatch=True)
        with self.assertRaisesRegex(ValueError,"Vendor overlay bytes mismatch"):
            self.assemble()
        self.assertFalse(self.out.exists())

    def test_manifest_pin(self):
        self.fixture()
        self.apin="0"*64
        with self.assertRaisesRegex(ValueError,"manifest pin mismatch"):
            self.assemble()

    def test_extra_boot_marker(self):
        self.fixture()
        write(self.android,"r800dev/android/BOOT_ANDROID",b"x",0o644)
        with self.assertRaisesRegex(ValueError,"Unexpected layer entry"):
            self.assemble()

    def test_changed_adaptation_bytes(self):
        self.fixture()
        (self.adaptation/"r800dev/start.sh").write_bytes(b"modified")
        with self.assertRaisesRegex(ValueError,"Adaptation bytes changed"):
            self.assemble()

    def test_changed_android_image(self):
        self.fixture()
        p=self.android/"r800dev/android/system.img"
        p.chmod(0o600)
        with p.open("r+b") as f:
            f.seek(0)
            f.write(b"changed")
        p.chmod(0o400)
        with self.assertRaisesRegex(ValueError,"SHA-256 mismatch"):
            self.assemble()


if __name__=="__main__":
    unittest.main()
