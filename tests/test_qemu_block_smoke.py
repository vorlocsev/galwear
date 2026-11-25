"""Host-side synthetic fixture orchestration tests; real boot is separate."""
import argparse
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"build"))
import r800_qemu_block_smoke as a
import r800_qemu_system_init as observer

class BlockSmokeTests(unittest.TestCase):
    def test_two_real_files_and_separate_status(self):
        with tempfile.TemporaryDirectory() as tmp:
            args=argparse.Namespace(fixture_dir=Path(tmp)/"fixtures",mke2fs="mke2fs",e2fsck="e2fsck")
            def boot(ns,policy,records,**kw):
                self.assertIsNone(policy)
                self.assertTrue(kw["synthetic"])
                self.assertEqual([d["name"] for d in records],["system","runtime"])
                for d in records:
                    self.assertEqual(d["path"].stat().st_size,a.SIZE)
                return {"status":"VIRT_SYNTHETIC_READONLY_BLOCK_MOUNTS_ONLY"}
            with patch.object(a,"invoke") as tool,patch.object(a.disk,"run_disks",side_effect=boot):
                result=a.run(args)
            self.assertEqual(tool.call_count,4)
            self.assertFalse(result["android_images_used"])

    def test_synthetic_rejects_policy(self):
        with self.assertRaisesRegex(ValueError,"Synthetic disk mode"):
            a.disk.run_disks(None,"policy",[],synthetic=True)

    def test_synthetic_rejects_label_parser(self):
        with self.assertRaisesRegex(ValueError,"Synthetic disk mode"):
            a.disk.run_disks(None,None,[],synthetic=True,label_parser=lambda *_: {})

    def test_live_explicit_guest_failure_stops_observer(self):
        for line in (b"r800-virt-disk: FAIL stage=mount name=system code=6",
                     b"r800-disk-label: FAIL path=/system/bin/init actual=bad"):
            with self.subTest(line=line):
                monitor = observer.LiveHeartbeat(0.0)
                with self.assertRaisesRegex(ValueError, "critical diagnostic"):
                    monitor.feed(line + b"\n", 1.0)

    def test_failure_stops_before_boot(self):
        with tempfile.TemporaryDirectory() as tmp:
            args=argparse.Namespace(fixture_dir=Path(tmp)/"fixtures",mke2fs="mke2fs",e2fsck="e2fsck")
            with patch.object(a,"invoke",side_effect=ValueError("format failed")),patch.object(a.disk,"run_disks") as boot:
                with self.assertRaisesRegex(ValueError,"format failed"):
                    a.run(args)
                boot.assert_not_called()

if __name__=="__main__":
    unittest.main()
