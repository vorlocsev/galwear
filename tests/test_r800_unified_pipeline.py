"""Exercise the unified local pipeline with real EXT4 and synthetic donor producers.

The real device staging, adaptation, Android mountpoint adaptation, Android
staging, integrated assembly, handover and readiness checks all run. Kernel
input is the existing synthetic CPIO/DTB/Image fixture; vendor producer and
Tizen producer are fixtures. No root mount, real donor or hardware access.
"""
from contextlib import ExitStack
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"build"))
import r800_build_local_development as pipeline
import r800_build_local_android as android_build
import r800_stage_device_layer as device
import r800_stage_adaptation_layer as adaptation
import r800_stage_integrated_development as integrated
import r800_stage_development_tree as tree
import r800_development_kernel as kernel
import r800_adapt_system_mountpoint as system_adapt
import r800_stage_android_layer as android_stage
import r800_review_handover as handover
import r800_installation_layout as installation
import r800_development_readiness as readiness
import test_r800_build_local_android as android_fixture
import test_r800_stage_integrated_development as kernel_fixture
import test_r800_stage_adaptation_layer as runtime_fixture
import test_r800_stage_development_tree as tree_fixture
import test_r800_display_asset_layer as asset_fixture

SOURCE="a"*40


class UnifiedPipelineTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root=Path(tmp.name)
        self.output=self.root/"output"
        self.a=android_fixture.LocalAndroidPipelineTests()
        self.a.setUp()
        self.addCleanup(self.a.doCleanups)
        self.k=kernel_fixture.IntegratedDevelopmentTests()
        self.k.setUp()
        self.addCleanup(self.k.doCleanups)
        self.r=runtime_fixture.AdaptationLayerTests()
        self.r.setUp()
        self.addCleanup(self.r.doCleanups)
        self.paths={"kernel":self.k.boot,"components":self.a.components,
                    "system":self.a.system,"base":self.a.base,"j4":self.a.j4,
                    "effects":self.a.effects,"tizen":self.root/"tizen.img",
                    "closure":self.root/"closure","ndk":self.root/"ndk"}
        self.paths["tizen"].write_bytes(b"synthetic Tizen input")
        for name in ("closure","ndk"):
            self.paths[name].mkdir()
        (self.paths["closure"]/pipeline.MANIFEST).write_bytes(b"synthetic closure")
        # Populate the actual device stage's expected compiled paths; binary
        # fixture content is not treated as a verified real compiled artifact.
        rows=dict(self.a.rows)
        for name in device.COMPILED:
            raw=tree_fixture.elf() if name.endswith(".so") else Path(name).name.encode()
            mode=0o755 if name.startswith("bin/") or name in device.CHARGER_TOOLS else 0o644
            key="payload/"+name
            tree_fixture.write(self.a.components,key,raw,mode)
            rows[key]={"bytes":len(raw),"sha256":pipeline.sha(raw),"mode":oct(mode)}
        for name in device.OVERLAY:
            key="vendor-overlay/"+name
            dest=device.destination(name)
            raw=tree_fixture.elf() if dest.endswith(".so") else Path(dest).name.encode()
            tree_fixture.write(self.a.components,key,raw,0o644)
            self.assertEqual(pipeline.sha(raw),rows[key]["sha256"])
        self.a.manifest=json.dumps({"files":rows}).encode()
        (self.a.components/"component-evidence.json").write_bytes(self.a.manifest)
        self.pins={n:pipeline.sha(self.paths[n].read_bytes())
                   for n in ("system","base","j4","effects","tizen")}
        self.pins.update(kernel=self.k.pin,components=pipeline.sha(self.a.manifest),
                         closure=pipeline.sha((self.paths["closure"]/pipeline.MANIFEST).read_bytes()))
        self.assets=self.root/"assets"
        self.assets_pin=asset_fixture.fixture(self.assets)

    def fake_runtime(self,image,image_sha,closure,closure_sha,ndk,out,source_sha,xtra_abi):
        self.assertEqual(image_sha,self.pins["tizen"])
        self.assertEqual(closure_sha,self.pins["closure"])
        out.mkdir()
        self.r.fixture(out,True)
        path=out/"tizen-runtime-evidence.json"
        report=json.loads(path.read_bytes())
        report.update(tizen_image_sha256=image_sha,closure_manifest_sha256=closure_sha)
        path.write_text(json.dumps(report))
        return report

    def fake_audit(self,bridge,lib):
        return {"status":"STATIC_GLIBC_CLOSURE_ONLY",
                "sha256":pipeline.sha(bridge.read_bytes()),
                "donor_sha256":{n:pipeline.sha((lib/n).read_bytes()) for n in adaptation.DONORS}}

    def context(self,stack):
        for module in (pipeline,android_build,device,adaptation,integrated,tree,kernel,
                       system_adapt,android_stage,handover,installation,readiness):
            stack.enter_context(patch.object(module,"checkout_sha"))
        for module in (pipeline,device,android_build):
            stack.enter_context(patch.object(module,"verify_components"))
        stack.enter_context(patch.object(pipeline,"stage_runtime",side_effect=self.fake_runtime))
        stack.enter_context(patch.object(adaptation,"audit",side_effect=self.fake_audit))
        stack.enter_context(patch.object(android_build,"build_vendor",side_effect=self.a.fake_vendor))

    def test_build_and_independent_readiness(self):
        with ExitStack() as stack:
            self.context(stack)
            result=pipeline.build(self.paths,self.pins,self.output,SOURCE,
                                  assets=self.assets,assets_sha=self.assets_pin)
            pin=pipeline.sha((self.output/"local-build-evidence.json").read_bytes())
            final=readiness.readiness(self.output,pin,SOURCE)
        self.assertEqual(result["status"],"LOCAL_GALWEAR_DEVELOPMENT_TREE_BUILT_STATIC_ONLY")
        self.assertEqual(final["checks"]["stage_chain"],"STATIC_PASS")
        self.assertEqual(final["checks"]["recovery_inputs"],"NOT_SUPPLIED")
        self.assertEqual(final["handover"]["checks"]["display_assets"],"STATIC_PASS")
        self.assertEqual(final["handover"]["missing_display_assets"],[])
        self.assertEqual(final["installation"]["partition_layout"]["p15"]["files"].keys(),
                         {"r800-android/vendor.img"})
        self.assertFalse(final["safe_to_flash"])
        self.assertFalse((self.output/"development/r800dev/android/BOOT_ANDROID").exists())

    def test_failed_runtime_does_not_publish(self):
        with ExitStack() as stack:
            self.context(stack)
            stack.enter_context(patch.object(pipeline,"stage_runtime",side_effect=ValueError("fixture failure")))
            with self.assertRaisesRegex(ValueError,"fixture failure"):
                pipeline.build(self.paths,self.pins,self.output,SOURCE)
        self.assertFalse(self.output.exists())
        self.assertEqual(list(self.root.glob("r800-local-build-*")),[])


if __name__=="__main__":
    unittest.main()
