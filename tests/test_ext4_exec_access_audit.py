"""Synthetic advisory policy and inherited stdout checks."""
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"build"))
import r800_ext4_exec_access_audit as a
import r800_ext4_console_contract as c

LABELS = {
    "/system/bin/linker64":"u:object_r:system_file:s0",
    "/system/lib64/libbase.so":"u:object_r:system_lib_file:s0",
    "/system/lib64/liblog.so":"u:object_r:system_lib_file:s0",
    "/apex/com.android.runtime/bin/linker64":"u:object_r:system_file:s0",
    "/apex/com.android.runtime/lib64/bionic/libc.so":"u:object_r:system_lib_file:s0",
}
SYSTEM = {"verified_system_entries":{"system/bin/linker64":{"type":"symlink"}}}
LOG = (b"start\nr800-console: stage=kernel device=5:1 inode=42 filesystem=0:1\n"
       b"exec\nr800-console: stage=init device=5:1 inode=42 filesystem=0:1\nend\n")

class AccessTests(unittest.TestCase):
    def test_deduplicates_libraries_and_preserves_paths(self):
        with patch.object(a,"label_plan",return_value=LABELS):
            plan=a.plan_checks(SYSTEM,{},{},"fixture")
        reasons=plan[("init","system_lib_file","file","map")]
        self.assertIn("/system/lib64/libbase.so",reasons)
        self.assertIn("/system/lib64/liblog.so",reasons)
        self.assertIn("/apex/com.android.runtime/lib64/bionic/libc.so",reasons)
        self.assertIn(("galwear_property_client","system_file","lnk_file","read"),plan)

    def test_stock_no_client_or_library_requirements(self):
        with patch.object(a,"label_plan",return_value=LABELS):
            plan=a.plan_checks(SYSTEM,{},{},"stock")
        self.assertTrue(all(k[0]=="init" and k[2]!="file" for k in plan))

    def test_missing_allow_is_advisory_only(self):
        with patch.object(a,"label_plan",return_value=LABELS), \
             patch.object(a,"allow",return_value={"unconditional_allow_found":False}):
            result=a.evaluate_blob(b"policy",SYSTEM,{},{},"fixture")
        self.assertEqual(result["status"],a.STATUS)
        self.assertGreater(result["missing_unconditional_allow_count"],0)
        self.assertFalse(result["runtime_access_tested"])
        self.assertFalse(result["actual_fd_opener_sid_verified"])

    def inspect(self,log):
        return c.inspect(log,("kernel","init"),(b"start",b"exec"),(b"exec",b"end"))

    def test_same_console(self):
        self.assertTrue(self.inspect(LOG)["inherited_stdout_identity_reported"])

    def test_null_or_changed_inode_rejected(self):
        for log in (LOG.replace(b"device=5:1",b"device=1:3"),
                    LOG.replace(b"stage=init device=5:1 inode=42",
                                b"stage=init device=5:1 inode=43")):
            with self.assertRaisesRegex(ValueError,"stdout identity changed"):
                self.inspect(log)

    def test_missing_and_misordered_console_rejected(self):
        with self.assertRaisesRegex(ValueError,"Missing or unavailable"):
            self.inspect(LOG.replace(b"r800-console: stage=init device=5:1 inode=42 filesystem=0:1\n",b""))
        with self.assertRaisesRegex(ValueError,"outside stage window"):
            self.inspect(LOG.replace(b"exec\n",b"").replace(b"end\n",b"exec\nend\n"))

if __name__=="__main__":
    unittest.main()
