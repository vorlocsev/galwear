"""Synthetic manifests; no original firmware or flashable image."""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"build"))
from r800_prepare_payload_inputs import prepare, COMPILED, RADIO, ASSET_SIZES
from test_r800_stage_components import arm_fixture, dex_fixture
from test_android_linker_audit import fixture

SHA = "a"*40

class PrepareInputsTests(unittest.TestCase):
    def setUp(self):
        t=tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        root=Path(t.name)
        self.components=root/"compiled"
        self.assets=root/"assets"
        self.radio=root/"radio"
        self.output=root/"out"
        cm,am,rm={},{},{}
        for name in COMPILED:
            if name.endswith(".so"):
                raw=fixture("arm")
            elif name.endswith(".dex"):
                raw=dex_fixture()
            elif name.startswith("bin/") or name.startswith("charger/"):
                raw=arm_fixture()
            else:
                raw=b"synthetic"
            key="payload/"+name
            cm[key]=self.put(self.components,key,raw)
        for name,size in ASSET_SIZES.items():
            am[name]=self.put(self.assets,name,bytes(size))
        for name in RADIO:
            key="payload/"+name
            rm[key]={**self.put(self.radio,key,b"synthetic radio"),"status":"EXTRACTED"}
        self.write(self.components/"component-evidence.json",{
            "status":"PARTIAL_COMPILED_COMPONENTS_ONLY","source_sha":SHA,
            "safe_to_flash":False,"files":cm})
        self.write(self.assets/"assets-evidence.json",am)
        self.write(self.radio/"ext4-evidence.json",{"profile":"tizen",
            "image_sha256":"b"*64,"safe_to_flash":False,"files":rm})

    def put(self,root,name,raw):
        p=root/name
        p.parent.mkdir(parents=True,exist_ok=True)
        p.write_bytes(raw)
        return {"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest(),
                "mode":oct(p.stat().st_mode&0o777)}

    def write(self,path,data):
        path.write_text(json.dumps(data))

    def stage(self):
        return prepare(self.components,self.assets,self.radio,self.output,SHA)

    def test_partial_tree(self):
        r=self.stage()
        self.assertEqual(set(r["files"]),COMPILED|RADIO|set(ASSET_SIZES))
        self.assertFalse(r["safe_to_flash"])
        self.assertFalse((self.output/"android").exists())
        self.assertFalse((self.output/"gpsbridge").exists())

    def test_asset_corruption(self):
        (self.assets/"charger/d0.rgb").write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError,"hash or size mismatch"):
            self.stage()
        self.assertFalse(self.output.exists())

    def test_missing_radio_evidence(self):
        p=self.radio/"ext4-evidence.json"
        r=json.loads(p.read_text())
        r["files"].pop("payload/fw/bcmdhd_sta.bin")
        self.write(p,r)
        with self.assertRaisesRegex(ValueError,"Missing verified radio"):
            self.stage()
        self.assertFalse(self.output.exists())

    def test_compiled_manifest_incomplete(self):
        p=self.components/"component-evidence.json"
        r=json.loads(p.read_text())
        key="payload/bin/iw"
        r["files"].pop(key)
        (self.components/key).unlink()
        self.write(p,r)
        with self.assertRaisesRegex(ValueError,"inventory incomplete"):
            self.stage()

    def test_no_overwrite(self):
        self.output.mkdir()
        with self.assertRaisesRegex(ValueError,"already exists"):
            self.stage()

if __name__=="__main__":
    unittest.main()
