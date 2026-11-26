"""Known-component tzlite audit; synthetic ELF metadata and real paths."""
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"build"))
import r800_tzlite_audit as t


class TzliteTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root=Path(temp.name)
        for guest in t.MOUNTPOINTS+t.REQUIRED_TREES:
            (self.root/guest.lstrip("/")).mkdir(parents=True,exist_ok=True)
        for guest in t.TARGETS:
            path=self.root/guest.lstrip("/")
            path.parent.mkdir(parents=True,exist_ok=True)
            path.write_bytes(b"fixture")
            path.chmod(0o755)
        for guest,raw in (("/etc/lhd/lhd.conf",b"fixture"),
                          ("/etc/gps-manager/brcm/gpsd.xml",b"<gpsd/>"),
                          ("/etc/passwd",b"location:x:5001:5002::/:/bin/false\n"),
                          ("/etc/group",b"location:x:5002:\n")):
            path=self.root/guest.lstrip("/")
            path.parent.mkdir(parents=True,exist_ok=True)
            path.write_bytes(raw)
        self.closure={"problems":[],"relocation_review_objects":[],
            "aliases":{n:n for n in t.TARGETS},
            "files":{n:{"arm_flags":0x05000200,"has_dynamic":True,
                         "dynamic_symbol_count":1,"elf_type":"ET_DYN",
                         "interpreter":"/lib/ld-linux.so.3" if n in t.PROGRAMS else None}
                     for n in t.TARGETS},
            "symbol_candidates":{"limit_exceeded":False,"targets":{
                n:{"inventory_incomplete":False,"incomplete":[],"missing_strong":[],"ambiguous":[]}
                for n in t.TARGETS}}}

    def check(self):
        with patch.object(t,"audit",return_value=self.closure) as audit:
            result=t.check(self.root)
        audit.assert_called_once_with(self.root,t.TARGETS)
        self.assertFalse(result["safe_to_flash"])
        self.assertFalse(result["gnss_runtime_verified"])
        return result

    def test_known_set(self):
        self.assertEqual(self.check()["status"],"TZLITE_KNOWN_STATIC_CANDIDATES_ONLY")
    def test_missing_plugin(self):
        del self.closure["files"]["/usr/lib/libbrcm.so"]
        self.assertIn("TZLITE_TARGET_MISSING:/usr/lib/libbrcm.so",self.check()["problems"])
    def test_missing_symbol(self):
        self.closure["symbol_candidates"]["targets"]["/usr/lib/libbrcm.so"]["missing_strong"]=["missing"]
        self.assertIn("TZLITE_SYMBOL_SCOPE_REVIEW:/usr/lib/libbrcm.so",self.check()["problems"])
    def test_wrong_loader(self):
        self.closure["files"]["/usr/bin/gpsd"]["interpreter"]=None
        self.assertIn("TZLITE_PROGRAM_INTERPRETER_REVIEW:/usr/bin/gpsd",self.check()["problems"])
    def test_wrong_plugin_type(self):
        self.closure["files"]["/usr/lib/libbrcm.so"]["elf_type"]="ET_EXEC"
        self.assertIn("TZLITE_PLUGIN_TYPE_REVIEW:/usr/lib/libbrcm.so",self.check()["problems"])
    def test_missing_mountpoint(self):
        (self.root/"run").rmdir()
        self.assertIn("TZLITE_DIRECTORY_REVIEW:/run",self.check()["problems"])
    def test_missing_config(self):
        (self.root/"etc/lhd/lhd.conf").unlink()
        self.assertIn("CONFIGURATION_REVIEW:/etc/lhd/lhd.conf",self.check()["problems"])
    def test_nonexecutable(self):
        (self.root/"usr/bin/lhd").chmod(0o644)
        self.assertIn("TZLITE_PROGRAM_MODE_REVIEW:/usr/bin/lhd",self.check()["problems"])
    def test_budget(self):
        self.closure["symbol_candidates"]["limit_exceeded"]=True
        self.assertIn("TZLITE_SYMBOL_BUDGET_EXCEEDED",self.check()["problems"])


if __name__=="__main__":
    unittest.main()
