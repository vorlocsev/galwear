"""Static host dependency inventory: synthetic reports, no target execution."""
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"build"))
import r800_linux_host_elf_lock as host

SOURCE="a"*40
TOOL="/usr/bin/fixture"
LIB="/usr/lib/x86_64-linux-gnu/libfixture.so"
LOADER="/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"
PIN="b"*64


class HostElfLockTests(unittest.TestCase):
    def setUp(self):
        self.lock={"source_sha":SOURCE,"tools":{"fixture":{"resolved":TOOL,"bytes":1,"sha256":PIN}}}
        self.report={"objects":{
            TOOL:{"bytes":1,"sha256":PIN,"needed":["libfixture.so"],"interpreter":host.LOADER},
            LIB:{"bytes":1,"sha256":PIN,"needed":[],"interpreter":None},
            LOADER:{"bytes":1,"sha256":PIN,"needed":[],"interpreter":None}},
            "bindings":{"fixture":TOOL,"libfixture.so":LIB,host.LOADER:LOADER},"problems":[]}

    def inventory(self):
        with patch.object(host,"TOOLS",("fixture",)), \
             patch.object(host,"audit",return_value=self.report), \
             patch.object(host.Path,"resolve",autospec=True,side_effect=lambda p,**kw:p), \
             patch.object(host,"digest",return_value={"bytes":1,"sha256":PIN}):
            return host.inventory(self.lock,SOURCE)

    def test_exact_candidates(self):
        result=self.inventory()
        self.assertEqual(result["status"],"SELECTED_HOST_ELF_CANDIDATES_ONLY")
        self.assertFalse(result["runtime_verified"])
        self.assertFalse(result["safe_to_flash"])

    def test_changed_tool(self):
        self.lock["tools"]["fixture"]["sha256"]="c"*64
        result=self.inventory()
        self.assertEqual(result["status"],"HOST_ELF_REVIEW_REQUIRED")
        self.assertIn("TOOL_LOCK_MISMATCH_OR_UNSUPPORTED_ELF",[p["reason"] for p in result["problems"]])

    def test_missing_dependency(self):
        del self.report["bindings"]["libfixture.so"]
        self.assertIn("UNRESOLVED_PROVIDER",[p["reason"] for p in self.inventory()["problems"]])

    def test_missing_loader(self):
        del self.report["bindings"][host.LOADER]
        self.assertIn("LOADER_NOT_IN_INVENTORY",[p["reason"] for p in self.inventory()["problems"]])

    def test_outside_library_root(self):
        self.report["objects"]["/tmp/libfixture.so"]=self.report["objects"].pop(LIB)
        self.report["bindings"]["libfixture.so"]="/tmp/libfixture.so"
        self.assertIn("OUTSIDE_APPROVED_HOST_PATHS",[p["reason"] for p in self.inventory()["problems"]])

    def test_ambiguous_dependency(self):
        self.report["problems"].append({"object":TOOL,"needed":"libfixture.so","reason":"AMBIGUOUS"})
        self.assertEqual(self.inventory()["status"],"HOST_ELF_REVIEW_REQUIRED")

    def test_wrong_head(self):
        self.lock["source_sha"]="0"*40
        with self.assertRaisesRegex(ValueError,"exact-head"):
            self.inventory()


if __name__=="__main__":
    unittest.main()
