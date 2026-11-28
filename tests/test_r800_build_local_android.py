"""Pipeline contract with real EXT4 adaptation/staging, synthetic vendor producer."""
import hashlib
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"build"))
import r800_build_local_android as pipeline
import r800_adapt_system_mountpoint as adapt
import r800_stage_android_layer as android
from r800_vendor_inputs import OVERLAY
from r800_compiled_overlay_ext4 import destination
from r800_donor_preflight import digest
import test_r800_adapt_system_mountpoint as system_fixture
import test_r800_stage_development_tree as vendor_fixture

SOURCE="a"*40


class LocalAndroidPipelineTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root=Path(tmp.name)
        self.output=self.root/"output"
        system=system_fixture.SystemMountpointTests()
        system.setUp()
        self.addCleanup(system.doCleanups)
        system.fixture()
        self.system=system.image
        vendor=vendor_fixture.DevelopmentTreeTests()
        vendor.setUp()
        self.addCleanup(vendor.doCleanups)
        vendor.fixture()
        self.vendor=vendor.android/"r800-android/vendor.img"
        self.components=self.root/"components"
        self.components.mkdir()
        rows={}
        for name in OVERLAY:
            raw=(vendor.adaptation/"vendor"/destination(name)).read_bytes()
            rows["vendor-overlay/"+name]={"bytes":len(raw),"sha256":pipeline.sha(raw),"mode":"0o644"}
        self.rows=rows
        self.manifest=json.dumps({"files":rows}).encode()
        (self.components/"component-evidence.json").write_bytes(self.manifest)
        self.base=self.root/"base.img"
        self.j4=self.root/"j4.img"
        self.effects=self.root/"effects.so"
        for p in (self.base,self.j4,self.effects):
            p.write_bytes(p.name.encode())
        self.pins={p:pipeline.sha(p.read_bytes()) for p in (self.system,self.base,self.j4,self.effects)}

    def fake_vendor(self,components,base,base_sha,j4,j4_sha,effects,effects_sha,system,system_sha,output,source_sha):
        output.mkdir()
        shutil.copyfile(self.vendor,output/"vendor.img")
        matches={"/"+destination(n):self.rows["vendor-overlay/"+n] for n in OVERLAY}
        recipe={}
        for name in ("input-evidence.json","recipe-preflight.json","merged-vendor-graph.json"):
            raw=b"{}"
            (output/name).write_bytes(raw)
            recipe[name]=pipeline.sha(raw)
        report={"source_sha":source_sha,"status":"LOCAL_VENDOR_CANDIDATE_OVERLAY_MATCH_ONLY",
                "safe_to_flash":False,"component_manifest_sha256":pipeline.sha(self.manifest),
                "donor_sha256":{"base":base_sha,"j4":j4_sha,"effects":effects_sha,"system":system_sha},
                "vendor":digest(output/"vendor.img"),"overlay_matches":matches,
                "recipe_evidence_sha256":recipe}
        (output/"vendor-build-evidence.json").write_text(json.dumps(report))
        return report

    def run_pipeline(self,producer=None):
        with patch.object(pipeline,"checkout_sha"),patch.object(pipeline,"verify_components"), \
             patch.object(adapt,"checkout_sha"),patch.object(android,"checkout_sha"), \
             patch.object(pipeline,"build_vendor",side_effect=producer or self.fake_vendor):
            return pipeline.build(self.components,self.system,self.pins[self.system],
                                  self.base,self.pins[self.base],self.j4,self.pins[self.j4],
                                  self.effects,self.pins[self.effects],self.output,SOURCE)

    def test_pipeline(self):
        result=self.run_pipeline()
        self.assertEqual(result["status"],"LOCAL_ANDROID_LAYER_BUILT_STATIC_ONLY")
        self.assertFalse(result["safe_to_flash"])
        self.assertEqual(len(result["overlay_matches"]),11)
        self.assertEqual(set(p.name for p in (self.output/"android").iterdir()),
                         {"r800dev","r800-android","android-layer-evidence.json"})
        self.assertTrue((self.output/"evidence/system-adaptation-evidence.json").is_file())
        self.assertEqual(pipeline.sha(self.system.read_bytes()),self.pins[self.system])

    def test_wrong_donor_pin(self):
        self.pins[self.effects]="0"*64
        with self.assertRaisesRegex(ValueError,"Original donor pin mismatch"):
            self.run_pipeline()
        self.assertFalse(self.output.exists())

    def test_wrong_vendor_provenance(self):
        def wrong(*args):
            result=self.fake_vendor(*args)
            result["donor_sha256"]["system"]="0"*64
            return result
        with self.assertRaisesRegex(ValueError,"Vendor recipe used different inputs"):
            self.run_pipeline(wrong)
        self.assertFalse(self.output.exists())

    def test_recipe_failure_no_output(self):
        def failed(*args):
            raise ValueError("Synthetic vendor recipe failure")
        with self.assertRaisesRegex(ValueError,"Synthetic vendor recipe failure"):
            self.run_pipeline(failed)
        self.assertFalse(self.output.exists())


if __name__=="__main__":
    unittest.main()
