"""Synthetic mount probe orchestration: mocked host commands, no root or mounts."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"build"))
import r800_synthetic_mount_probe as probe

SOURCE="a"*40
PIN="b"*64


class SyntheticMountProbeTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root=Path(tmp.name)
        self.before={"prerequisites":{"blockers":[]}}
        self.commands=[]

    def fake_command(self,args,timeout):
        self.commands.append(args)
        result=json.dumps({n:True for n in probe.CHECKS}) if args[0]=="unshare" else ""
        return subprocess.CompletedProcess(args,0,stdout=result)

    def invoke(self,*,detach=True,command=None,review=None):
        with patch.dict(probe.os.environ,probe.ENV), \
             patch.object(probe,"checkout_sha"), \
             patch.object(probe,"verify",return_value=self.before if review is None else review), \
             patch.object(probe,"command",side_effect=command or self.fake_command), \
             patch.object(probe,"detached",return_value=detach), \
             patch.object(probe.subprocess,"run",return_value=subprocess.CompletedProcess([],32)):
            return probe.probe(self.root,self.root/"lock.json",PIN,SOURCE)

    def test_exact_checks(self):
        result=self.invoke()
        self.assertEqual(result["status"],"SYNTHETIC_EXT4_MOUNT_XATTR_PASS_ONLY")
        self.assertTrue(result["loop_detached_and_workspace_removed"])
        self.assertEqual(set(result["checks"]),set(probe.CHECKS)|{"offline_fsck"})
        self.assertFalse(result["safe_to_flash"])
        self.assertFalse(result["vendor_build_verified"])
        self.assertEqual(list(self.root.iterdir()),[])
        self.assertEqual([a[0] for a in self.commands],["mkfs.ext4","unshare","e2fsck"])
        self.assertIn("--propagation",self.commands[1])
        self.assertIn("private",self.commands[1])

    def test_missing_prerequisites(self):
        with self.assertRaisesRegex(ValueError,"Host prerequisites review"):
            self.invoke(review={"prerequisites":{"blockers":["no loop"]}})
        self.assertEqual(self.commands,[])
        self.assertEqual(list(self.root.iterdir()),[])

    def test_incomplete_child_checks(self):
        def command(args,timeout):
            result=self.fake_command(args,timeout)
            if args[0]=="unshare":
                result.stdout='{"private_namespace":true}'
            return result
        result=self.invoke(command=command)
        self.assertEqual(result["status"],"REVIEW_REQUIRED")
        self.assertIn("Incomplete synthetic mount checks",result["error"])
        self.assertTrue(result["loop_detached_and_workspace_removed"])
        self.assertNotIn("e2fsck",[a[0] for a in self.commands])

    def test_unshare_failure(self):
        def command(args,timeout):
            if args[0]=="unshare":
                raise subprocess.CalledProcessError(1,args)
            return self.fake_command(args,timeout)
        result=self.invoke(command=command)
        self.assertEqual(result["status"],"REVIEW_REQUIRED")
        self.assertTrue(result["loop_detached_and_workspace_removed"])

    def test_loop_association_retained(self):
        result=self.invoke(detach=False)
        self.assertEqual(result["status"],"REVIEW_REQUIRED")
        self.assertFalse(result["loop_detached_and_workspace_removed"])
        self.assertTrue(Path(result["retained_fixture"]).is_dir())
        self.assertNotIn("e2fsck",[a[0] for a in self.commands])

    def test_wrong_path(self):
        with patch.dict(probe.os.environ,{"PATH":"/tmp"}):
            with patch.object(probe,"checkout_sha"):
                with self.assertRaisesRegex(ValueError,"documented system PATH"):
                    probe.probe(self.root,self.root/"lock.json",PIN,SOURCE)


if __name__=="__main__":
    unittest.main()
