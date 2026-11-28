"""Synthetic stage graph tests, not actual donor provenance or hardware evidence."""
import copy
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


if __name__=="__main__":
    unittest.main()
