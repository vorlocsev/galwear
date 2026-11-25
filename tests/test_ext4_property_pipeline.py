"""Synthetic EXT4 pipeline orchestration; no real AOSP or QEMU run."""
import argparse
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"build"))
import r800_ext4_property_pipeline as a

class Recorder:
    source_commit="test"
    status="RUNNING"
    def __init__(self, root, fail=None):
        self.out=root
        self.calls=[]
        self.fail=fail
    def step(self,name,command,*args):
        self.calls.append((name,command))
        if name==self.fail:
            raise ValueError("injected stage failure")
    def py(self,name,script,args,report,status,*extra):
        self.step(name,[script,*args,"--report",report,status])

class Ext4PipelineTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root=Path(temp.name)
        self.args=argparse.Namespace(build_root=self.root/"build", choices=self.root/"choices",
                    kernel=self.root/"Image",baseline=self.root/"baseline",
                    config_evidence=self.root/"config")
        for branch in ("stock","fixture"):
            host=self.args.build_root/branch/"host/bin"
            host.mkdir(parents=True)
            for name in ("e2fsdroid","checkfc","sepolicy-analyze"):
                (host/name).touch()

    def exercise(self, p):
        with patch.object(a,"verify_build"),patch.object(a,"block_config"), \
             patch.object(a,"runtime_apex",return_value=(self.root/"runtime.apex","a"*64)), \
             patch.object(a,"resolved_output",side_effect=lambda build,name:build/name):
            a.execute(p,self.args)

    def test_order_and_success(self):
        p=Recorder(self.root/"out")
        self.exercise(p)
        names=[n for n,_ in p.calls]
        self.assertLess(names.index("04-readonly-mount"),names.index("05-effective-labels"))
        self.assertLess(names.index("05-effective-labels"),names.index("07-init-transition"))
        self.assertLess(names.index("07-init-transition"),names.index("08-fixture-system"))
        self.assertEqual(names[-1],"09-property-service")
        self.assertEqual(p.status,a.SUCCESS)

    def test_failure_stops_before_service(self):
        p=Recorder(self.root/"out",fail="05-effective-labels")
        with self.assertRaisesRegex(ValueError,"injected"):
            self.exercise(p)
        self.assertNotEqual(p.status,a.SUCCESS)
        self.assertEqual(p.calls[-1][0],"05-effective-labels")

    def test_separate_stock_and_fixture(self):
        p=Recorder(self.root/"out")
        self.exercise(p)
        calls=dict(p.calls)
        self.assertNotIn("--service-fixture",calls["03-stock-system"])
        self.assertIn("--service-fixture",calls["08-fixture-system"])
        self.assertIn(self.args.build_root/"stock/product",calls["03-stock-system"])
        self.assertIn(self.args.build_root/"fixture/product",calls["08-fixture-system"])

    def test_transition_uses_exact_controls(self):
        p=Recorder(self.root/"out")
        self.exercise(p)
        args=dict(p.calls)["07-init-transition"]
        self.assertEqual(args[args.index("--original-system-report")+1],p.out/"03-stock-system.json")
        self.assertEqual(args[args.index("--system-report")+1],p.out/"transition-system.json")
        self.assertEqual(args.count("--system-report"),1)
        self.assertEqual(args[args.index("--label-report")+1],p.out/"labels.json")

    def test_compile_flags_distinct(self):
        p=Recorder(self.root/"out")
        a.compile_probes(p)
        calls=dict(p.calls)
        self.assertNotIn("-DGALWEAR_LABEL_PROBE",calls["02-01-compile-mount"])
        self.assertIn("-DGALWEAR_TRANSITION_PROBE",calls["02-03-compile-transition"])
        self.assertNotIn("-DGALWEAR_TRANSITION_PROBE",calls["02-05-compile-service"])
        self.assertIn("-DGALWEAR_SERVICE_PROBE",calls["02-05-compile-service"])

    def test_block_config_rejects_property(self):
        with patch.object(a,"verify_baseline",return_value="kernel"), \
             patch.object(a,"read_bounded_json",return_value={"status":"VIRT_CONFIG_STATIC_ONLY",
                "profile":"property","compiled_kernel_sha256":"kernel","safe_to_flash":False}):
            with self.assertRaisesRegex(ValueError,"block-profile"):
                a.block_config(self.args)

    def test_apex_digest_mismatch(self):
        build=self.args.build_root/"runtime"
        path=build/"aosp-out/apex"
        path.parent.mkdir(parents=True)
        path.write_bytes(b"donor")
        (build/"runtime-apex-path.txt").write_text(str(path)+"\n")
        with patch.object(a,"require_report",return_value={"apex_sha256":"wrong"}):
            with self.assertRaisesRegex(ValueError,"identity/path"):
                a.runtime_apex(self.args.build_root)

if __name__=="__main__":
    unittest.main()
