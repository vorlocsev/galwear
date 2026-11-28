"""Integrated development composition with synthetic kernel and EXT4 fixtures."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"build"))
import r800_stage_integrated_development as stage
import r800_development_kernel as kernel
import r800_stage_development_tree as tree
import test_r800_stage_development_tree as tree_fixture
from r800_cpio_audit import inspect_cpio
from r800_initramfs_spec import validate_init
from test_r800_boot_candidate import dtb, kernel as image_header
from test_initramfs_recipe import fake_aarch64_elf
from test_cpio_audit import make_newc

SOURCE="a"*40


class IntegratedDevelopmentTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root=Path(tmp.name)
        self.boot=self.root/"kernel"
        self.out=self.root/"result"
        initramfs=self.boot/"initramfs"
        initramfs.mkdir(parents=True)
        init=fake_aarch64_elf()
        archive=make_newc([("dev",0o040755,b""),("dev/console",0o020600,b""),
            ("proc",0o040555,b""),("sys",0o040555,b""),("data",0o040755,b""),
            ("init",0o100755,init)])
        (initramfs/"init").write_bytes(init)
        (initramfs/"initramfs.cpio").write_bytes(archive)
        baseline=(ROOT/"src/kernel/r800.config").read_text()
        template=baseline.replace(kernel.SOURCE_CONFIG,kernel.PLACEHOLDER)
        (initramfs/"development.config.in").write_text(template)
        files={name:{"sha256":stage.sha((initramfs/name).read_bytes()),
                     "bytes":(initramfs/name).stat().st_size}
               for name in ("init","initramfs.cpio","development.config.in")}
        evidence={"schema":"galwear-r800-development-initramfs-v1",
            "status":"FUNCTIONAL_INIT_COMPILED_CPIO_STAGED_ONLY","source_sha":SOURCE,
            "boot_profile":"DEVELOPMENT_FUNCTIONAL_UNTESTED","storage_write_capable":True,
            "kernel_compiled":False,"init_executed":False,"android_handover_tested":False,
            "safe_to_flash":False,"files":files,
            "source_sha256":{n:stage.sha((ROOT/n).read_bytes()) for n in
                ("src/initramfs/init.c","src/initramfs/build.sh","src/kernel/r800.config")},
            "init":validate_init(initramfs/"init"),
            "cpio":inspect_cpio(initramfs/"initramfs.cpio",initramfs/"init")}
        (initramfs/"development-initramfs-evidence.json").write_text(json.dumps(evidence))
        config=self.boot/"obj/.config"
        image=self.boot/"obj/arch/arm64/boot/Image"
        cpio=self.boot/"obj/usr/initramfs_data.cpio"
        image.parent.mkdir(parents=True)
        cpio.parent.mkdir()
        config.write_text(template.replace(kernel.PLACEHOLDER,
            'CONFIG_INITRAMFS_SOURCE="'+str(initramfs/"initramfs.cpio")+'"'))
        image.write_bytes(image_header()+archive)
        cpio.write_bytes(archive)
        (self.boot/"r800.dtb").write_bytes(dtb())
        with patch.object(kernel,"checkout_sha"):
            kernel.finalize(initramfs,config,image,self.boot/"r800.dtb",cpio,
                            self.boot/stage.REPORT,SOURCE)
        self.pin=stage.sha((self.boot/stage.REPORT).read_bytes())

    def mutate(self, **changes):
        path=self.boot/stage.REPORT
        report=json.loads(path.read_text())
        report.update(changes)
        path.write_text(json.dumps(report))
        self.pin=stage.sha(path.read_bytes())

    def test_integrated_fixture(self):
        fixture=tree_fixture.DevelopmentTreeTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        fixture.fixture()
        with patch.object(stage,"checkout_sha"),patch.object(kernel,"checkout_sha"),patch.object(tree,"checkout_sha"):
            result=stage.assemble(self.boot,self.pin,fixture.adaptation,fixture.apin,
                                  fixture.android,fixture.bpin,self.out,SOURCE)
        self.assertEqual(result["status"],"FUNCTIONAL_KERNEL_AND_ANDROID_TREE_STAGED_ONLY")
        self.assertEqual(len(result["kernel_files"]),5)
        self.assertTrue((self.out/"r800dev/android/system.img").is_file())
        self.assertTrue((self.out/"development-boot/Image").is_file())
        self.assertFalse((self.out/"r800dev/android/BOOT_ANDROID").exists())
        self.assertFalse(result["safe_to_flash"])

    def handover_fixture(self):
        fixture=tree_fixture.DevelopmentTreeTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        fixture.fixture()
        with patch.object(stage,"checkout_sha"),patch.object(kernel,"checkout_sha"),patch.object(tree,"checkout_sha"):
            stage.assemble(self.boot,self.pin,fixture.adaptation,fixture.apin,
                           fixture.android,fixture.bpin,self.out,SOURCE)
        return stage.sha((self.out/"integrated-development-evidence.json").read_bytes())

    def test_final_handover_review(self):
        import r800_review_handover as handover
        pin=self.handover_fixture()
        with patch.object(handover,"checkout_sha"):
            result=handover.review(self.out,pin,SOURCE)
        self.assertEqual(result["status"],"HOLD_HARDWARE_UNVERIFIED")
        self.assertEqual(result["checks"]["tree_inventory"],"PASS")
        self.assertEqual(result["checks"]["android_switch_root"],"NOT_TESTED")
        self.assertEqual(result["checks"]["local_runtime_startup"],"NOT_TESTED")
        self.assertIn("splash.raw",result["missing_display_assets"])
        self.assertFalse(result["safe_to_flash"])

    def test_handover_rejects_modified_file(self):
        import r800_review_handover as handover
        pin=self.handover_fixture()
        target=self.out/"r800dev/start.sh"
        target.write_bytes(b"modified")
        with patch.object(handover,"checkout_sha"), self.assertRaisesRegex(ValueError,"Tree member changed"):
            handover.review(self.out,pin,SOURCE)

    def test_handover_rejects_boot_marker(self):
        import r800_review_handover as handover
        pin=self.handover_fixture()
        (self.out/"r800dev/android/BOOT_ANDROID").touch()
        with patch.object(handover,"checkout_sha"), self.assertRaisesRegex(ValueError,"Unexpected tree entry"):
            handover.review(self.out,pin,SOURCE)

    def test_handover_rejects_reference_startup(self):
        import r800_review_handover as handover
        with self.assertRaisesRegex(ValueError,"Local runtime observation scope"):
            handover.runtime_observations(
                {"schema":"galwear-r800-loader-qemu-v1","status":"ARM32_LOADER_LIST_PASS"},
                {"schema":"galwear-r800-runtime-entry-qemu-v1","status":"REFERENCE_NEGATIVE_ENTRY_PASS"},
                "a"*64,SOURCE)

    def test_stale_kernel_source(self):
        self.mutate(source_sha="b"*40)
        with self.assertRaisesRegex(ValueError,"same-head functional"):
            stage.kernel_inputs(self.boot,self.pin,SOURCE,self.root)

    def test_diagnostic_profile_rejected(self):
        self.mutate(boot_profile="STORAGE_ISOLATED_DIAGNOSTIC")
        with self.assertRaisesRegex(ValueError,"same-head functional"):
            stage.kernel_inputs(self.boot,self.pin,SOURCE,self.root)

    def test_changed_kernel_rejected(self):
        image=self.boot/"obj/arch/arm64/boot/Image"
        image.write_bytes(image.read_bytes()+b"modified")
        with patch.object(kernel,"checkout_sha"),self.assertRaisesRegex(ValueError,"evidence differs"):
            stage.kernel_inputs(self.boot,self.pin,SOURCE,self.root)

    def test_wrong_evidence_pin(self):
        with self.assertRaisesRegex(ValueError,"pin mismatch"):
            stage.kernel_inputs(self.boot,"0"*64,SOURCE,self.root)


if __name__=="__main__":
    unittest.main()
