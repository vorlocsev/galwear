"""Development recovery binding tests with synthetic PIT and local fixture bytes."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"build"))
import r800_development_recovery as recovery
from test_installer_guard import fake_pit
from test_stage11_recovery import with_partition

SOURCE="a"*40
TREE="b"*64


class DevelopmentRecoveryTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root=Path(tmp.name)
        self.pit=self.root/"saved.pit"
        self.pit.write_bytes(fake_pit())
        self.layout=self.root/"layout.json"
        self.plan={"schema":"galwear-r800-installation-layout-v1",
                   "status":"HOLD_HARDWARE_UNVERIFIED","source_sha":SOURCE,
                   "safe_to_flash":False,
                   "storage_estimate":{"partitions":{"p15":{"logical_file_bytes":4096},
                                                     "p17":{"logical_file_bytes":8192}}}}
        self.layout.write_text(json.dumps(self.plan))
        self.files={}
        self.pins={}
        for name in recovery.ARTIFACTS:
            p=self.root/name
            p.write_bytes(name.encode())
            self.files[name]=p
            self.pins[name]=recovery.sha(p.read_bytes())

    def review(self,*,pit_pin=None,expected=None):
        with patch.object(recovery,"checkout_sha"),patch.object(recovery,"prepare",
                return_value=self.plan if expected is None else expected):
            return recovery.review_recovery(self.root,TREE,self.layout,
                recovery.sha(self.layout.read_bytes()),self.pit,
                recovery.sha(self.pit.read_bytes()) if pit_pin is None else pit_pin,
                self.files,self.pins,SOURCE)

    def test_synthetic_binding_is_hold(self):
        report=self.review()
        self.assertEqual(report["status"],"HOLD_HARDWARE_UNVERIFIED")
        self.assertEqual(report["partition_mapping"]["p15"]["pit_identifier"],15)
        self.assertIsNone(report["partition_mapping"]["p18"]["planned_logical_bytes"])
        self.assertEqual(set(report["artifact_sha256"]),set(recovery.ARTIFACTS))
        for flag in ("pit_linux_partition_mapping_verified","rollback_artifacts_verified",
                     "artifact_format_or_authenticity_verified","recovery_tested","safe_to_flash"):
            self.assertFalse(report[flag])

    def test_pit_pin_mismatch(self):
        with self.assertRaisesRegex(ValueError,"PIT pin mismatch"):
            self.review(pit_pin="0"*64)

    def test_layout_mismatch(self):
        with self.assertRaisesRegex(ValueError,"differs from recomputed"):
            self.review(expected={**self.plan,"safe_to_flash":True})

    def test_artifact_changed(self):
        self.files["dzImage"].write_bytes(b"modified")
        with self.assertRaisesRegex(ValueError,"artifact pin mismatch"):
            self.review()

    def test_wrong_pit_id(self):
        self.pit.write_bytes(fake_pit(overrides={"csc.img":99}))
        with self.assertRaisesRegex(ValueError,"Unexpected PIT mapping"):
            self.review()

    def test_protected_collision(self):
        self.pit.write_bytes(with_partition(fake_pit(),name="CSA",identifier=15))
        with self.assertRaisesRegex(ValueError,"identifier conflict"):
            self.review()

    def test_nonprotected_overlap(self):
        self.pit.write_bytes(with_partition(fake_pit(),name="EXTRA",identifier=99,
                                            offset=16384*9,blocks=8))
        with self.assertRaisesRegex(ValueError,"range overlap"):
            self.review()


if __name__=="__main__":
    unittest.main()
