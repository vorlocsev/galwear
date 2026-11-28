"""Display asset intake and propagation tests; no original screen art."""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"build"))
import r800_display_asset_layer as assets
import test_r800_stage_adaptation_layer as adaptation_fixture
import test_r800_stage_development_tree as tree_fixture


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def fixture(root):
    root.mkdir()
    rows={}
    for name,size in assets.ASSET_SIZES.items():
        raw=(b"\0\0\0\xff"*(size//4)) if name=="splash.raw" else b"\0"*size
        p=root/name
        p.parent.mkdir(parents=True,exist_ok=True)
        p.write_bytes(raw)
        rows[name]={"bytes":size,"sha256":sha(raw)}
    raw=json.dumps(rows).encode()
    (root/assets.MANIFEST).write_bytes(raw)
    return sha(raw)


class DisplayAssetLayerTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root=Path(tmp.name)
        self.assets=self.root/"assets"
        self.pin=fixture(self.assets)

    def test_exact_intake(self):
        result=assets.load_assets(self.assets,self.pin)
        self.assertEqual(set(result),set(assets.ASSETS))
        self.assertEqual(len(result),13)

    def test_bad_manifest_pin(self):
        with self.assertRaisesRegex(ValueError,"pin mismatch"):
            assets.load_assets(self.assets,"0"*64)

    def test_bad_alpha_even_with_updated_pin(self):
        path=self.assets/"splash.raw"
        raw=bytearray(path.read_bytes())
        raw[3]=0
        path.write_bytes(raw)
        manifest=self.assets/assets.MANIFEST
        rows=json.loads(manifest.read_bytes())
        rows["splash.raw"]["sha256"]=sha(raw)
        new=json.dumps(rows).encode()
        manifest.write_bytes(new)
        with self.assertRaisesRegex(ValueError,"alpha"):
            assets.load_assets(self.assets,sha(new))

    def test_partial_asset_layer(self):
        with self.assertRaisesRegex(ValueError,"Incomplete display asset"):
            assets.asset_modes({"assets_manifest_sha256":self.pin},{"r800dev/splash.raw":{}})

    def test_adaptation_and_development_tree(self):
        a=adaptation_fixture.AdaptationLayerTests()
        a.setUp()
        self.addCleanup(a.doCleanups)
        data=assets.load_assets(self.assets,self.pin)
        def add(report):
            for name,raw in data.items():
                p=a.device/name
                p.parent.mkdir(parents=True,exist_ok=True)
                p.write_bytes(raw)
                p.chmod(0o644)
                report["files"][name]={"bytes":len(raw),"sha256":sha(raw),"mode":"0o644"}
            report["total_bytes"]=sum(r["bytes"] for r in report["files"].values())
            report["assets_manifest_sha256"]=self.pin
        a.mutate(False,add)
        result=a.run_stage()
        self.assertEqual(result["assets_manifest_sha256"],self.pin)
        self.assertEqual(set(assets.ASSETS)&set(result["files"]),set(assets.ASSETS))
        self.assertFalse(result["safe_to_flash"])
        # Use the established EXT4 fixture to exercise the downstream composition.
        f=tree_fixture.DevelopmentTreeTests()
        f.setUp()
        self.addCleanup(f.doCleanups)
        f.fixture()
        manifest=f.adaptation/"adaptation-layer-evidence.json"
        report=json.loads(manifest.read_bytes())
        for name,raw in data.items():
            p=f.adaptation/name
            p.parent.mkdir(parents=True,exist_ok=True)
            p.write_bytes(raw)
            p.chmod(0o644)
            report["files"][name]={**result["files"][name]}
        report["total_bytes"]=sum(r["bytes"] for r in report["files"].values())
        report["assets_manifest_sha256"]=self.pin
        raw=json.dumps(report).encode()
        manifest.write_bytes(raw)
        f.apin=sha(raw)
        final=f.assemble()
        self.assertEqual(final["assets_manifest_sha256"],self.pin)
        for name,raw in data.items():
            self.assertEqual((f.out/name).read_bytes(),raw)
        self.assertFalse(final["safe_to_flash"])


if __name__=="__main__":
    unittest.main()
