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
import r800_bind_stock_donor as stock_binding
import r800_bind_pixel_system as pixel_binding
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
        self.assertEqual(final["checks"]["stock_donor_evidence"],"NOT_SUPPLIED")
        self.assertEqual(final["checks"]["pixel_system_evidence"],"NOT_SUPPLIED")
        self.assertEqual(final["handover"]["checks"]["display_assets"],"STATIC_PASS")
        self.assertEqual(final["handover"]["missing_display_assets"],[])
        self.assertEqual(final["installation"]["partition_layout"]["p15"]["files"].keys(),
                         {"r800-android/vendor.img"})
        self.assertFalse(final["safe_to_flash"])
        self.assertFalse((self.output/"development/r800dev/android/BOOT_ANDROID").exists())

    def test_failed_final_readiness_does_not_publish(self):
        with ExitStack() as stack:
            self.context(stack)
            check=stack.enter_context(patch.object(readiness,"readiness",
                side_effect=ValueError("fixture readiness rejection")))
            with self.assertRaisesRegex(ValueError,"fixture readiness rejection"):
                pipeline.build(self.paths,self.pins,self.output,SOURCE)
            check.assert_called_once()
        self.assertFalse(self.output.exists())
        self.assertEqual(list(self.root.glob("r800-local-build-*")),[])

    def test_failed_runtime_does_not_publish(self):
        with ExitStack() as stack:
            self.context(stack)
            stack.enter_context(patch.object(pipeline,"stage_runtime",side_effect=ValueError("fixture failure")))
            with self.assertRaisesRegex(ValueError,"fixture failure"):
                pipeline.build(self.paths,self.pins,self.output,SOURCE)
        self.assertFalse(self.output.exists())
        self.assertEqual(list(self.root.glob("r800-local-build-*")),[])


    def stock_fixture(self):
        # Synthetic reports match the fixture byte pins. The live image
        # validator is mocked here; real EXT4 verification has its own tests.
        result={}
        for name,(role,filename) in stock_binding.INPUTS.items():
            raw={"bytes":self.paths[name].stat().st_size,"sha256":self.pins[name]}
            archive={"bytes":raw["bytes"]+1024,"sha256":"e"*64}
            fs={"kind":"EXT4"}
            data={"schema":"galwear-r800-stock-donor-v1",
                  "status":"STOCK_PARTITION_CANDIDATE_ONLY","source_sha":SOURCE,
                  "role":role,"member":filename,"archive":archive,
                  "member_identity":raw,"decompressed_identity":raw,
                  "normalization":{"source_sha256":raw["sha256"],"source_bytes":raw["bytes"],
                                   "raw_sha256":raw["sha256"],"raw_bytes":raw["bytes"]},
                  "partition":{"file":filename,**raw},"filesystem":fs,
                  "android_identity":{"filesystem":fs} if name=="j4" else None,
                  **{k:False for k in stock_binding.FALSE_FLAGS}}
            path=self.root/(name+"-stock.json")
            path.write_text(json.dumps(data))
            result[name]=(path,pipeline.sha(path.read_bytes()),archive["sha256"])
        return result

    def fake_stock(self,image,image_pin,report,report_pin,archive_pin,name,source_sha):
        self.assertEqual(image_pin,pipeline.sha(image.read_bytes()))
        self.assertEqual(report_pin,pipeline.sha(report.read_bytes()))
        return stock_binding.describe(json.loads(report.read_bytes()),image_pin,
                                      report_pin,archive_pin,name,source_sha)

    def test_build_with_stock_evidence(self):
        stock=self.stock_fixture()
        with ExitStack() as stack:
            self.context(stack)
            check=stack.enter_context(patch.object(pipeline,"verify_stock",side_effect=self.fake_stock))
            result=pipeline.build(self.paths,self.pins,self.output,SOURCE,stock_evidence=stock)
            summary=self.output/"local-build-evidence.json"
            final=readiness.readiness(self.output,pipeline.sha(summary.read_bytes()),SOURCE)
        self.assertEqual(check.call_count,4)
        self.assertEqual(set(result["stock_donor_bindings"]),{"tizen","j4"})
        self.assertEqual(final["checks"]["stock_donor_evidence"],"SAVED_REPORT_CHAIN_ONLY")
        self.assertFalse(final["original_donor_authenticity_verified"])
        self.assertFalse(final["safe_to_flash"])

    def test_partial_stock_evidence_rejected(self):
        stock=self.stock_fixture()
        with ExitStack() as stack:
            self.context(stack)
            with self.assertRaisesRegex(ValueError,"Supply both stock donor reports"):
                pipeline.build(self.paths,self.pins,self.output,SOURCE,
                               stock_evidence={"tizen":stock["tizen"]})
        self.assertFalse(self.output.exists())

    def test_stock_evidence_rehashed_summary_rejected(self):
        stock=self.stock_fixture()
        with ExitStack() as stack:
            self.context(stack)
            stack.enter_context(patch.object(pipeline,"verify_stock",side_effect=self.fake_stock))
            pipeline.build(self.paths,self.pins,self.output,SOURCE,stock_evidence=stock)
            summary=self.output/"local-build-evidence.json"
            data=json.loads(summary.read_bytes())
            data["stock_donor_bindings"]["j4"]["image"]["bytes"]+=1
            summary.write_text(json.dumps(data))
            with self.assertRaisesRegex(ValueError,"Saved stock binding differs"):
                readiness.readiness(self.output,pipeline.sha(summary.read_bytes()),SOURCE)


    def pixel_fixture(self):
        raw={"bytes":self.paths["system"].stat().st_size,"sha256":self.pins["system"]}
        fs={"kind":"EXT4","partition_bytes":raw["bytes"]}
        factory=pixel_binding.FACTORY_SHA256
        identity={"schema":"galwear-r800-partition-identity-v1","source_sha":SOURCE,
                  "partition":"system","image_sha256":raw["sha256"],"filesystem":fs,
                  **{k:False for k in ("donor_authenticity_verified","wear_os_runtime_verified",
                                       "hardware_tested","safe_to_flash")}}
        data={"schema":"galwear-r800-pixel-raw-donor-v1","status":pixel_binding.STATUS,
              "source_sha":SOURCE,"factory_sha256":factory,"documented_factory_pin_matched":True,
              "factory_extraction":{"status":"PIXEL_DONOR_EXTRACTED_ONLY","factory_sha256":factory,
                 "nested_zip":{"bytes":4096,"sha256":"e"*64},"images":{"system.img":raw},
                 "system_adaptation_verified":False,"vendor_compatibility_verified":False,
                 "safe_to_flash":False},
              "mode":"direct","metadata_slot":None,"super_extraction":None,
              "partitions":{"system":{"file":"system.img",**raw,"filesystem":fs,"identity":identity,
                 "provenance":{"format":"raw","source_sha256":raw["sha256"],"source_bytes":raw["bytes"],
                               "raw_sha256":raw["sha256"],"raw_bytes":raw["bytes"]}}},
              **{k:False for k in pixel_binding.FLAGS}}
        path=self.root/"pixel-stock.json"
        path.write_text(json.dumps(data))
        return path,pipeline.sha(path.read_bytes())

    def fake_pixel(self,image,image_pin,report,report_pin,source_sha):
        self.assertEqual(image_pin,pipeline.sha(image.read_bytes()))
        self.assertEqual(report_pin,pipeline.sha(report.read_bytes()))
        return pixel_binding.describe(json.loads(report.read_bytes()),image_pin,report_pin,source_sha)

    def test_build_with_all_donor_evidence(self):
        pixel=self.pixel_fixture()
        stock=self.stock_fixture()
        with ExitStack() as stack:
            self.context(stack)
            check=stack.enter_context(patch.object(pipeline,"verify_pixel",side_effect=self.fake_pixel))
            stack.enter_context(patch.object(pipeline,"verify_stock",side_effect=self.fake_stock))
            result=pipeline.build(self.paths,self.pins,self.output,SOURCE,
                                  stock_evidence=stock,pixel_evidence=pixel)
            summary=self.output/"local-build-evidence.json"
            final=readiness.readiness(self.output,pipeline.sha(summary.read_bytes()),SOURCE)
        self.assertEqual(check.call_count,2)
        self.assertEqual(final["checks"]["pixel_system_evidence"],"SAVED_REPORT_CHAIN_ONLY")
        self.assertEqual(final["checks"]["stock_donor_evidence"],"SAVED_REPORT_CHAIN_ONLY")
        self.assertEqual(result["pixel_system_binding"],final["pixel_system_binding"])
        self.assertFalse(final["safe_to_flash"])

    def test_rehashed_pixel_binding_summary_rejected(self):
        pixel=self.pixel_fixture()
        with ExitStack() as stack:
            self.context(stack)
            stack.enter_context(patch.object(pipeline,"verify_pixel",side_effect=self.fake_pixel))
            pipeline.build(self.paths,self.pins,self.output,SOURCE,pixel_evidence=pixel)
            summary=self.output/"local-build-evidence.json"
            data=json.loads(summary.read_bytes())
            data["pixel_system_binding"]["image"]["bytes"]+=1
            summary.write_text(json.dumps(data))
            with self.assertRaisesRegex(ValueError,"Saved Pixel binding differs"):
                readiness.readiness(self.output,pipeline.sha(summary.read_bytes()),SOURCE)


if __name__=="__main__":
    unittest.main()
