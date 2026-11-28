"""Explicit dynamic plugin closure tests using synthetic ARM ELF and real EXT4."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"build"))
import r800_tizen_plugins as plugins
from r800_stage_tizen import stage
from r800_verify_tizen_stage import verify, MANIFEST
from test_android_linker_audit import fixture


class TizenPluginTests(unittest.TestCase):
    plugin="/usr/lib/sensor/plugin.so"

    def setUp(self):
        tmp=tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root=Path(tmp.name)
        self.donor=self.root/"donor"
        self.output=self.root/"stage"
        for name,data in {
            "/usr/bin/lhd":fixture("arm"),
            self.plugin:fixture("arm",needed=["libx.so"]),
            "/usr/lib/libx.so":fixture("arm",sonames=["libx.so"]),
        }.items():
            path=self.donor/name.lstrip("/")
            path.parent.mkdir(parents=True,exist_ok=True)
            path.write_bytes(data)

    def stage(self):
        return stage(self.donor,self.output,["/usr/bin/lhd"],plugins=[self.plugin])

    def image(self):
        path=self.root/"rootfs.img"
        subprocess.run(["mke2fs","-q","-F","-t","ext4","-d",str(self.donor),str(path),"8192"],
                       check=True,capture_output=True)
        return path,hashlib.sha256(path.read_bytes()).hexdigest()

    def test_selected_plugin_and_dependency(self):
        report=self.stage()
        self.assertIn("/usr/lib/libx.so",report["files"])
        self.assertEqual(report["selected_plugins"][self.plugin]["needed"],["libx.so"])
        self.assertFalse(report["plugins_complete"])
        self.assertFalse(verify(self.output)["safe_to_flash"])

    def test_missing_dependency(self):
        (self.donor/"usr/lib/libx.so").unlink()
        with self.assertRaisesRegex(ValueError,"Unresolved Tizen dependency closure"):
            self.stage()
        self.assertFalse(self.output.exists())

    def test_invalid_plugin_path(self):
        for path in ("/usr/bin/lhd","/usr/lib/../plugin.so","/etc/plugin.so"):
            with self.subTest(path=path),self.assertRaises(ValueError):
                plugins.plugin_paths([path])

    def test_wrong_abi(self):
        (self.donor/self.plugin.lstrip("/")).write_bytes(fixture("arm64"))
        with self.assertRaises(ValueError):
            self.stage()

    def test_plugin_metadata_rechecked(self):
        self.stage()
        manifest=self.output/MANIFEST
        report=json.loads(manifest.read_text())
        report["selected_plugins"][self.plugin]["needed"]=[]
        manifest.write_text(json.dumps(report))
        with self.assertRaisesRegex(ValueError,"Selected plugin evidence mismatch"):
            verify(self.output)

    def test_same_image_binding(self):
        report=self.stage()
        path,pin=self.image()
        result=plugins.bind_canonical_image(path,pin,report["files"],self.root)
        self.assertEqual(set(result["canonical_members"]),set(report["files"]))
        self.assertTrue(result["canonical_image_bytes_match"])
        self.assertFalse(result["image_alias_topology_verified"])

    def test_mixed_donor_rejected(self):
        report=self.stage()
        path=self.donor/"usr/lib/libx.so"
        data=bytearray(path.read_bytes())
        data[-1]^=1
        path.write_bytes(data)
        image,pin=self.image()
        with self.assertRaisesRegex(ValueError,"Canonical ELF differs"):
            plugins.bind_canonical_image(image,pin,report["files"],self.root)


if __name__=="__main__":
    unittest.main()
