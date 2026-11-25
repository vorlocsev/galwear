"""Synthetic policy fixture checks; no AOSP policy compilation."""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "build"))
import r800_galwear_policy_fixture as a

FIXTURE = Path(__file__).resolve().parents[1] / "src/android/sepolicy"

class FixtureTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        (self.root / "property_contexts").write_text("debug. u:object_r:debug_prop:s0\n")
        (self.root / "file_contexts").write_text("/system(/.*)? u:object_r:system_file:s0\n")

    def test_overlay(self):
        a.verify_overlay(self.root, FIXTURE)

    def test_existing_exact_property(self):
        (self.root / "property_contexts").write_text("ro.property_service.version u:object_r:default_prop:s0\n")
        with self.assertRaisesRegex(ValueError, "Existing exact"):
            a.verify_overlay(self.root, FIXTURE)

    def test_existing_exact_file(self):
        (self.root / "file_contexts").write_text(a.FILE+" u:object_r:system_file:s0\n")
        with self.assertRaisesRegex(ValueError, "Existing exact"):
            a.verify_overlay(self.root, FIXTURE)

    def test_fixture_has_distinct_negative_type(self):
        self.assertNotEqual(a.PROPERTIES["debug.galwear.service"],
                            a.PROPERTIES["debug.galwear.denied"])
        self.assertEqual(a.PROPERTIES["ro.galwear.service.fixture"],
                         a.PROPERTIES["debug.galwear.service"])
        te = (FIXTURE/"galwear_property_client.te").read_text()
        self.assertIn("init_daemon_domain(galwear_property_client)", te)
        self.assertIn("neverallow galwear_property_client galwear_denied_prop:property_service set;", te)
        self.assertNotIn("permissive ", te)

    def test_audit_rejects_permissive_domain(self):
        rel = "vendor/etc/selinux/precompiled_sepolicy"
        p = self.root / rel
        p.parent.mkdir(parents=True)
        p.write_bytes(b"policy")
        plat = self.root / "system/etc/selinux"
        plat.mkdir(parents=True)
        props = (FIXTURE/"property_contexts").read_bytes()
        (plat/"plat_property_contexts").write_bytes(props)
        (plat/"plat_file_contexts").write_bytes((FIXTURE/"file_contexts").read_bytes())
        tool = self.root/"tool"
        tool.write_bytes(b"tool")
        evidence = {"policy_path": rel, "policy_sha256": a.sha(b"policy"),
                    "property_contexts_sha256": {"system/etc/selinux/plat_property_contexts": a.sha(props)}}
        for permissive in ("", a.DOMAIN+"\n"):
            with patch.object(a, "audit", return_value=evidence), \
                 patch.object(a.subprocess, "run", side_effect=[
                     subprocess.CompletedProcess([], 0),
                     subprocess.CompletedProcess([], 0, stdout=permissive)]):
                if permissive:
                    with self.assertRaisesRegex(ValueError, "permissive"):
                        a.audit_fixture(self.root, tool, tool)
                else:
                    result = a.audit_fixture(self.root, tool, tool)
                    self.assertFalse(result["stock_policy"])
                    self.assertFalse(result["client_mac_denial_tested"])

if __name__ == "__main__":
    unittest.main()
