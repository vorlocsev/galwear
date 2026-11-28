"""Synthetic environment lock tests: no mounts, root operations or tool execution."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"build"))
import r800_linux_assembly_environment as env

SOURCE="a"*40


class EnvironmentTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root=Path(tmp.name)
        self.lock=self.root/"lock.json"
        self.data={"schema":env.SCHEMA,"source_sha":SOURCE,"fixture":True,
                   "complete_environment_verified":False,"safe_to_flash":False}
        self.lock.write_text(json.dumps(self.data))
        self.pin=env.hashlib.sha256(self.lock.read_bytes()).hexdigest()

    def verify(self,blockers=(),observed=None):
        with patch.object(env,"identity",return_value=self.data if observed is None else observed), \
             patch.object(env,"prerequisites",return_value={"blockers":list(blockers)}):
            return env.verify(self.lock,self.pin,SOURCE)

    def test_exact_lock(self):
        result=self.verify()
        self.assertEqual(result["status"],"SELECTED_HOST_TOOLS_MATCH_PREREQUISITES_UNTESTED")
        self.assertFalse(result["reproducible_build_verified"])
        self.assertFalse(result["safe_to_flash"])

    def test_wrong_pin(self):
        self.pin="0"*64
        with self.assertRaisesRegex(ValueError,"lock SHA-256 mismatch"):
            self.verify()

    def test_changed_tool_identity(self):
        with self.assertRaisesRegex(ValueError,"environment differs"):
            self.verify(observed={**self.data,"fixture":False})

    def test_root_prerequisite_blocked(self):
        result=self.verify(["Root required"])
        self.assertEqual(result["status"],"HOST_PREREQUISITES_REVIEW_REQUIRED")

    def test_changed_during_verification(self):
        with patch.object(env,"identity",side_effect=[self.data,{**self.data,"fixture":False}]):
            with self.assertRaisesRegex(ValueError,"changed during verification"):
                env.verify(self.lock,self.pin,SOURCE)

    def test_missing_tool(self):
        with patch.object(env.shutil,"which",return_value=None):
            with self.assertRaisesRegex(ValueError,"Missing host tool"):
                env.executable("git")

    def test_path_escape(self):
        p=self.root/"tool"
        p.write_bytes(b"fixture")
        p.chmod(0o755)
        with patch.object(env.shutil,"which",return_value=str(p)):
            with self.assertRaisesRegex(ValueError,"outside system directories"):
                env.executable("git")

    def test_allowed_tool(self):
        p=self.root/"tool"
        p.write_bytes(b"fixture")
        p.chmod(0o755)
        with patch.object(env,"SYSTEM_DIRS",(self.root,)), \
             patch.object(env.shutil,"which",return_value=str(p)):
            row=env.executable("git")
        self.assertEqual(row["sha256"],env.hashlib.sha256(b"fixture").hexdigest())

    def test_symlink_escape(self):
        system=self.root/"system"
        system.mkdir()
        target=self.root/"external"
        target.write_bytes(b"fixture")
        target.chmod(0o755)
        path=system/"git"
        path.symlink_to(target)
        with patch.object(env,"SYSTEM_DIRS",(system,)), \
             patch.object(env.shutil,"which",return_value=str(path)):
            with self.assertRaisesRegex(ValueError,"outside system directories"):
                env.executable("git")


    def saved_fixture(self):
        lock={"schema":env.SCHEMA,"source_sha":SOURCE,"os":dict(env.OS),
              "architecture":"x86_64","python_version":"3.12.3",
              "tools":{n:{"bytes":1,"sha256":"a"*64,"resolved":"/usr/bin/"+n} for n in env.TOOLS},
              "complete_environment_verified":False,"dynamic_libraries_verified":False,
              "safe_to_flash":False}
        probe={"schema":"galwear-r800-synthetic-mount-probe-v1","source_sha":SOURCE,
               "environment_lock_sha256":self.pin,"status":"SYNTHETIC_EXT4_MOUNT_XATTR_PASS_ONLY",
               "checks":{n:True for n in env.PROBE_CHECKS},
               "loop_detached_and_workspace_removed":True,"retained_fixture":None,"error":None,
               **{n:False for n in ("donor_images_used","physical_devices_used","vendor_build_verified",
                                    "reproducible_build_verified","hardware_tested","safe_to_flash")}}
        return lock,probe

    def test_saved_host_chain(self):
        lock,probe=self.saved_fixture()
        self.assertEqual(env.saved_environment(lock,probe,self.pin,SOURCE),
                         "SAVED_HOST_LOCK_AND_SYNTHETIC_PROBE_ONLY")

    def test_saved_wrong_lock(self):
        lock,probe=self.saved_fixture()
        probe["environment_lock_sha256"]="0"*64
        with self.assertRaisesRegex(ValueError,"scope or lock binding"):
            env.saved_environment(lock,probe,self.pin,SOURCE)

    def test_saved_missing_check(self):
        lock,probe=self.saved_fixture()
        del probe["checks"]["unmount"]
        with self.assertRaisesRegex(ValueError,"Incomplete saved synthetic"):
            env.saved_environment(lock,probe,self.pin,SOURCE)

    def test_saved_failed_cleanup(self):
        lock,probe=self.saved_fixture()
        probe["loop_detached_and_workspace_removed"]=False
        with self.assertRaisesRegex(ValueError,"scope or lock binding"):
            env.saved_environment(lock,probe,self.pin,SOURCE)

    def test_saved_wrong_head(self):
        lock,probe=self.saved_fixture()
        probe["source_sha"]="0"*40
        with self.assertRaisesRegex(ValueError,"scope or lock binding"):
            env.saved_environment(lock,probe,self.pin,SOURCE)

    def test_saved_missing_tool(self):
        lock,probe=self.saved_fixture()
        del lock["tools"]["git"]
        with self.assertRaisesRegex(ValueError,"Host tool inventory"):
            env.saved_environment(lock,probe,self.pin,SOURCE)

    def test_saved_claimed_reproducibility(self):
        lock,probe=self.saved_fixture()
        probe["reproducible_build_verified"]=True
        with self.assertRaisesRegex(ValueError,"scope or lock binding"):
            env.saved_environment(lock,probe,self.pin,SOURCE)


if __name__=="__main__":
    unittest.main()
