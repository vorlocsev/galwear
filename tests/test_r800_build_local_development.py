"""Local build orchestration contract, no actual donors or root mounts."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"build"))
import r800_build_local_development as pipeline

SOURCE="a"*40


class LocalDevelopmentTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root=Path(tmp.name)
        self.output=self.root/"output"
        self.paths={}
        self.pins={}
        for name in ("kernel","components","closure","ndk"):
            self.paths[name]=self.root/name
            self.paths[name].mkdir()
        for name,manifest in (("kernel","development-kernel-evidence.json"),
                              ("components","component-evidence.json"),("closure",pipeline.MANIFEST)):
            raw=name.encode()
            (self.paths[name]/manifest).write_bytes(raw)
            self.pins[name]=pipeline.sha(raw)
        for name in ("system","base","j4","effects","tizen"):
            p=self.root/(name+".img")
            p.write_bytes(name.encode())
            self.paths[name]=p
            self.pins[name]=pipeline.sha(p.read_bytes())

    def preflight(self):
        with patch.object(pipeline,"checkout_sha"),patch.object(pipeline,"verify_components"):
            return pipeline.preflight(self.paths,self.pins,self.output,SOURCE)

    def test_explicit_inputs(self):
        self.assertEqual(self.preflight(),(self.paths,self.output))

    def test_missing_pin(self):
        del self.pins["tizen"]
        with self.assertRaisesRegex(ValueError,"Explicit SHA-256"):
            self.preflight()

    def test_changed_donor(self):
        self.paths["system"].write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError,"Donor pin mismatch: system"):
            self.preflight()

    def test_changed_kernel_manifest(self):
        (self.paths["kernel"]/"development-kernel-evidence.json").write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError,"manifest pin mismatch: kernel"):
            self.preflight()

    def test_output_inside_components(self):
        self.output=self.paths["components"]/"nested"
        with self.assertRaisesRegex(ValueError,"Fresh output outside"):
            self.preflight()

    def test_reject_stale_stage(self):
        report={"source_sha":"b"*40,"status":"expected","safe_to_flash":False}
        with self.assertRaisesRegex(ValueError,"Unexpected stage scope"):
            pipeline.bind(self.root,"test.json",report,SOURCE,"expected")

    def test_reject_changed_stage_evidence(self):
        report={"source_sha":SOURCE,"status":"expected","safe_to_flash":False}
        (self.root/"test.json").write_text(json.dumps({**report,"safe_to_flash":True}))
        with self.assertRaisesRegex(ValueError,"Stage evidence mismatch"):
            pipeline.bind(self.root,"test.json",report,SOURCE,"expected")

    def test_kernel_failure_precedes_vendor_build(self):
        with patch.object(pipeline,"checkout_sha"),patch.object(pipeline,"verify_components"), \
             patch.object(pipeline,"kernel_inputs",side_effect=ValueError("Invalid kernel")), \
             patch.object(pipeline,"stage_device") as device, \
             patch.object(pipeline,"build_android") as android:
            with self.assertRaisesRegex(ValueError,"Invalid kernel"):
                pipeline.build(self.paths,self.pins,self.output,SOURCE)
            device.assert_not_called()
            android.assert_not_called()
        self.assertFalse(self.output.exists())


if __name__=="__main__":
    unittest.main()
