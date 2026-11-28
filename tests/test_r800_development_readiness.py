"""Synthetic stage graph tests, not actual donor provenance or hardware evidence."""
import copy
import json
import tempfile
from pathlib import Path
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"build"))
import r800_development_readiness as ready


class DevelopmentReadinessTests(unittest.TestCase):
    def setUp(self):
        names=sorted(set(ready.STAGES)|ready.RECIPE)
        pins={n:("%064x"%(i+1)) for i,n in enumerate(names)}
        inputs={n:("%064x"%(i+100)) for i,n in enumerate(
            ("kernel","components","system","base","j4","effects","tizen","closure"))}
        inputs["kernel"]=pins["development-kernel-evidence.json"]
        self.summary={"stage_evidence_sha256":pins,"input_sha256":inputs}
        def row(n,mode="0o644"):
            return {"sha256":"%064x"%n,"bytes":n,"mode":mode}
        kernel={n:row(i+1000,"0o400") for i,n in enumerate(
            ("Image","r800.dtb","effective.config","init","initramfs.generated"))}
        device={"r800dev/start.sh":row(20,"0o755")}
        runtime={"r800dev/gpsbridge":row(21,"0o755")}
        android={"r800dev/android/system.img":row(22,"0o400"),
                 "r800-android/vendor.img":row(23,"0o400")}
        def image(name):
            return {k:v for k,v in android[name].items() if k!="mode"}
        system=image("r800dev/android/system.img")
        vendor=image("r800-android/vendor.img")
        adapted={**{n:{**r,"layer":"device"} for n,r in device.items()},
                 **{n:{**r,"layer":"tizen-runtime"} for n,r in runtime.items()}}
        self.integrated={"kernel_evidence_sha256":inputs["kernel"],
                         "kernel_files":{"development-boot/"+n:r for n,r in kernel.items()}}
        self.userspace={"adaptation_manifest_sha256":pins["adaptation-layer-evidence.json"],
                        "android_manifest_sha256":pins["android-layer-evidence.json"],
                        "files":{**adapted,**{n:{**r,"layer":"android"} for n,r in android.items()}},
                        "vendor_overlay_matches":{}}
        self.reports={
            "development-kernel-evidence.json":{
                "components":{"kernel_sha256":kernel["Image"]["sha256"],
                              "kernel_bytes":kernel["Image"]["bytes"],
                              "dtb_sha256":kernel["r800.dtb"]["sha256"],
                              "dtb_bytes":kernel["r800.dtb"]["bytes"]},
                "config_sha256":kernel["effective.config"]["sha256"],
                "init_sha256":kernel["init"]["sha256"],
                "generated_cpio":{"archive_sha256":kernel["initramfs.generated"]["sha256"]}},
            "device-layer-evidence.json":{"component_manifest_sha256":inputs["components"],"files":device},
            "tizen-runtime-evidence.json":{"tizen_image_sha256":inputs["tizen"],
                "closure_manifest_sha256":inputs["closure"],"files":runtime},
            "adaptation-layer-evidence.json":{"device_manifest_sha256":pins["device-layer-evidence.json"],
                "runtime_manifest_sha256":pins["tizen-runtime-evidence.json"],"files":adapted},
            "android-build-evidence.json":{"component_manifest_sha256":inputs["components"],
                "android_layer_evidence_sha256":pins["android-layer-evidence.json"],
                "system_adaptation_evidence_sha256":pins["system-adaptation-evidence.json"],
                "vendor_build_evidence_sha256":pins["vendor-build-evidence.json"],
                "original_donor_sha256":{n:inputs[n] for n in ("system","base","j4","effects")},
                "files":android,"overlay_matches":{}},
            "android-layer-evidence.json":{"files":android},
            "system-adaptation-evidence.json":{"original":{"sha256":inputs["system"]},"system":system},
            "vendor-build-evidence.json":{"component_manifest_sha256":inputs["components"],
                "recipe_evidence_sha256":{n:pins[n] for n in ready.RECIPE},
                "donor_sha256":{**{n:inputs[n] for n in ("base","j4","effects")},"system":system["sha256"]},
                "vendor":vendor,"overlay_matches":{}},
        }
        self.reports=copy.deepcopy(self.reports)
        self.userspace=copy.deepcopy(self.userspace)

    def verify(self):
        return ready.chain(self.summary,self.reports,self.integrated,self.userspace)

    def test_exact_chain(self):
        self.assertTrue(self.verify())

    def test_stale_runtime(self):
        self.reports["adaptation-layer-evidence.json"]["runtime_manifest_sha256"]="0"*64
        with self.assertRaisesRegex(ValueError,"Stage evidence chain"):
            self.verify()

    def test_changed_kernel(self):
        self.integrated["kernel_files"]["development-boot/Image"]["sha256"]="0"*64
        with self.assertRaisesRegex(ValueError,"Final kernel"):
            self.verify()

    def test_wrong_system_donor(self):
        self.reports["system-adaptation-evidence.json"]["original"]["sha256"]="0"*64
        with self.assertRaisesRegex(ValueError,"Final Android images"):
            self.verify()

    def test_changed_final_member(self):
        self.userspace["files"]["r800dev/gpsbridge"]["sha256"]="0"*64
        with self.assertRaisesRegex(ValueError,"Final member differs"):
            self.verify()

    def test_added_final_member(self):
        self.userspace["files"]["r800dev/extra"]={"bytes":1,"sha256":"a"*64,"mode":"0o644"}
        with self.assertRaisesRegex(ValueError,"Stage inventory"):
            self.verify()

    def test_asset_binding_mismatch(self):
        self.summary["assets_manifest_sha256"]="a"*64
        with self.assertRaisesRegex(ValueError,"Display asset chain"):
            self.verify()


    def managed_fixture(self):
        source="a"*40
        stock={n:{"report_sha256":"b"*64,"reported_archive_sha256":"c"*64}
               for n in ("j4","tizen")}
        pixel={"report_sha256":"d"*64}
        tools={n:"e"*64 for n in ready.NDK_KEYS}
        ndk={"schema":"galwear-r800-ndk-selected-tools-v1",
             "status":"SELECTED_NDK_TOOL_PINS_MATCH_ONLY","revision":ready.NDK_REVISION,
             "files":{n:{"bytes":32,"sha256":v,
                         "resolved":n if n=="source.properties" else (ready.NDK_BIN/n).as_posix()}
                      for n,v in tools.items()},
             **{k:False for k in ("complete_ndk_verified","host_libraries_verified",
                                   "upstream_authenticity_verified","safe_to_flash")}}
        self.summary.update(stock_donor_bindings=stock,pixel_system_binding=pixel,
                            ndk_selected_tool_evidence=ndk,xtra_abi=0)
        data={"schema":"galwear-r800-local-donor-manifest-v1","source_sha":source,
              "inputs":{**{n:{"path":"inputs/"+n,"sha256":h}
                           for n,h in self.summary["input_sha256"].items()},
                        "ndk":{"path":"tools/ndk","tools_sha256":tools}},
              "evidence":{"system":{"path":"reports/pixel.json","sha256":pixel["report_sha256"]},
                          **{n:{"path":"reports/"+n+".json","sha256":row["report_sha256"],
                                "archive_sha256":row["reported_archive_sha256"]} for n,row in stock.items()}},
              "xtra_abi":0,"assets":None}
        return source,data

    def managed_review(self,source,data):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            name="managed-donor-manifest.json"
            raw=json.dumps(data).encode()
            (root/name).write_bytes(raw)
            pin=ready.sha(raw)
            self.summary["managed_manifest_sha256"]=pin
            self.summary["stage_evidence_sha256"][name]=pin
            return ready.managed_chain(self.summary,root,source)

    def test_managed_manifest_exact_chain(self):
        source,data=self.managed_fixture()
        self.assertEqual(self.managed_review(source,data),
                         ("SAVED_MANIFEST_CHAIN_ONLY","SAVED_SELECTED_TOOL_PINS_MATCH_MANIFEST"))

    def test_managed_manifest_rehashed_input_mismatch(self):
        source,data=self.managed_fixture()
        data["inputs"]["system"]["sha256"]="f"*64
        with self.assertRaisesRegex(ValueError,"Managed manifest input pin mismatch"):
            self.managed_review(source,data)

    def test_managed_manifest_rehashed_ndk_mismatch(self):
        source,data=self.managed_fixture()
        data["inputs"]["ndk"]["tools_sha256"]["clang"]="f"*64
        with self.assertRaisesRegex(ValueError,"Managed manifest NDK pin mismatch"):
            self.managed_review(source,data)

    def test_managed_manifest_rehashed_report_mismatch(self):
        source,data=self.managed_fixture()
        data["evidence"]["j4"]["sha256"]="f"*64
        with self.assertRaisesRegex(ValueError,"Managed report pin mismatch"):
            self.managed_review(source,data)

    def test_managed_manifest_archive_mismatch(self):
        source,data=self.managed_fixture()
        data["evidence"]["tizen"]["archive_sha256"]="f"*64
        with self.assertRaisesRegex(ValueError,"Managed archive pin mismatch"):
            self.managed_review(source,data)

    def test_managed_manifest_xtra_mismatch(self):
        source,data=self.managed_fixture()
        data["xtra_abi"]=1
        with self.assertRaisesRegex(ValueError,"Managed manifest XTRA ABI mismatch"):
            self.managed_review(source,data)

    def test_managed_manifest_unsafe_path(self):
        source,data=self.managed_fixture()
        data["inputs"]["ndk"]["path"]="../ndk"
        with self.assertRaisesRegex(ValueError,"Invalid managed relative path"):
            self.managed_review(source,data)

    def test_managed_manifest_ndk_scope(self):
        source,data=self.managed_fixture()
        self.summary["ndk_selected_tool_evidence"]["complete_ndk_verified"]=True
        with self.assertRaisesRegex(ValueError,"Unexpected NDK evidence scope"):
            self.managed_review(source,data)

    def test_unmanaged_no_manifest(self):
        self.assertEqual(ready.managed_chain(self.summary,Path("."),"a"*40),
                         ("NOT_SUPPLIED","NOT_SUPPLIED"))


if __name__=="__main__":
    unittest.main()
