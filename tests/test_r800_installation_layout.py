"""Offline layout planning contracts; no installation or device access."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"build"))
import r800_installation_layout as layout


class InstallationLayoutTests(unittest.TestCase):
    def setUp(self):
        def row(n,mode="0o644"):
            return {"bytes":n,"sha256":"a"*64,"mode":mode}
        self.files={"r800-android/vendor.img":row(4096,"0o400"),
                    "r800dev/android/system.img":row(8192,"0o400"),
                    "r800dev/bin/busybox":row(32,"0o755"),
                    "vendor/lib/hw/gps.r800.so":row(32)}
        self.dirs={"r800dev/tzlite/dev":"0o755"}
        self.kernel={"development-boot/Image":row(1024,"0o400"),
                     "development-boot/r800.dtb":row(133120,"0o400")}

    def plan(self):
        return layout.plan(self.files,self.dirs,self.kernel)

    def test_exact_placement(self):
        result=self.plan()
        self.assertEqual(set(result["partition_layout"]),{"p15","p17"})
        self.assertEqual(set(result["partition_layout"]["p15"]["files"]),{"r800-android/vendor.img"})
        self.assertEqual(set(result["partition_layout"]["p17"]["files"]),
                         {"r800dev/android/system.img","r800dev/bin/busybox"})
        self.assertEqual(result["preserve_partitions"],["p16","p18"])
        self.assertEqual(result["excluded_build_provenance"],["vendor/lib/hw/gps.r800.so"])
        self.assertFalse(result["installation_authorized"])
        self.assertFalse(result["safe_to_flash"])

    def test_conflict_requires_review(self):
        for row in self.plan()["partition_layout"].values():
            self.assertEqual(row["conflict_policy"],"HOLD_IF_EXISTING_TARGET")
            self.assertFalse(row["apply_authorized"])

    def test_image_modes_are_intended_not_changed(self):
        result=self.plan()
        self.assertEqual(result["partition_layout"]["p15"]["files"]["r800-android/vendor.img"]["intended_mode"],"0o644")
        self.assertEqual(self.files["r800-android/vendor.img"]["mode"],"0o400")
        self.assertEqual(result["partition_layout"]["p17"]["files"]["r800dev/bin/busybox"]["intended_mode"],"0o755")

    def test_state_excluded(self):
        for name in ("BOOT_ANDROID","persistent.img","userdata.img","RESET_DATA","hook.sh"):
            path="r800dev/android/"+name
            self.files[path]={"bytes":1,"sha256":"b"*64,"mode":"0o644"}
            with self.subTest(path=path),self.assertRaisesRegex(ValueError,"stateful deployment"):
                self.plan()
            del self.files[path]

    def test_traversal_rejected(self):
        self.files["r800dev/../userdata"]={"bytes":1,"sha256":"b"*64,"mode":"0o644"}
        with self.assertRaisesRegex(ValueError,"Unsafe"):
            self.plan()

    def test_preserve_recovery_hold(self):
        result=self.plan()
        self.assertFalse(result["rollback_artifacts_verified"])
        self.assertFalse(result["recovery_tested"])
        self.assertFalse(result["boot_container_created"])
        self.assertFalse(result["payload_created"])
        self.assertIn("r800dev/tzlite/dev",result["partition_layout"]["p17"]["directories"])


if __name__=="__main__":
    unittest.main()
