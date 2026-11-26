"""Atomic candidate staging with synthetic audit results, no privileged operations."""
import hashlib
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"build"))
import r800_stage_tzlite as s


class StageTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.parent=Path(temp.name)
        self.root=self.parent/"donor"
        self.root.mkdir()
        self.output=self.parent/"output"
        self.elf="/usr/bin/lhd"
        self.alias="/bin/lhd"
        self.payload=b"fixture ELF"
        self.put(self.elf,self.payload,0o755)
        (self.root/"bin").mkdir()
        (self.root/"bin/lhd").symlink_to("../usr/bin/lhd")
        self.config={}
        for name in s.CONFIGS:
            raw=b"fixture config"
            self.put(name,raw)
            self.config[name]=self.record(raw)
        self.report={"schema":"r800-tzlite-audit-v1",
                     "status":"TZLITE_KNOWN_STATIC_CANDIDATES_ONLY",
                     "problems":[],"safe_to_flash":False,
                     "dependency_evidence":{"files":{self.elf:self.record(self.payload)},
                                            "aliases":{self.elf:self.elf,self.alias:self.elf}},
                     "configuration_evidence":{"files":self.config}}

    def put(self,name,raw,mode=0o644):
        path=self.root/name.lstrip("/")
        path.parent.mkdir(parents=True,exist_ok=True)
        path.write_bytes(raw)
        path.chmod(mode)

    @staticmethod
    def record(raw):
        return {"sha256":hashlib.sha256(raw).hexdigest(),"bytes":len(raw)}

    def run_stage(self,side_effect=None):
        with patch.object(s.os,"geteuid",return_value=1000), \
             patch.object(s,"check",return_value=self.report,side_effect=side_effect):
            return s.stage(self.root,self.output)

    def test_success(self):
        result=self.run_stage()
        self.assertEqual(result["status"],"TZLITE_STATIC_CANDIDATE_ONLY")
        self.assertEqual((self.output/"bin/lhd").read_bytes(),self.payload)
        self.assertTrue((self.output/"bin/lhd").is_symlink())
        self.assertFalse(result["safe_to_flash"])
        self.assertFalse(result["ownership_preserved"])
        self.assertTrue((self.output/"tzlite-static-evidence.json").is_file())

    def test_existing_output(self):
        self.output.mkdir()
        with self.assertRaises(ValueError): self.run_stage()

    def test_output_inside_source(self):
        self.output=self.root/"output"
        with self.assertRaises(ValueError): self.run_stage()

    def test_source_audit_failure(self):
        self.report["problems"]=["missing"]
        with self.assertRaises(ValueError): self.run_stage()
        self.assertFalse(self.output.exists())

    def test_staged_audit_failure(self):
        failed=dict(self.report,problems=["missing"])
        with self.assertRaises(ValueError): self.run_stage([self.report,failed])
        self.assertFalse(self.output.exists())

    def test_source_hash_changed(self):
        self.put(self.elf,b"changed")
        with self.assertRaises(ValueError): self.run_stage()
        self.assertFalse(self.output.exists())

    def test_config_hash_changed(self):
        self.put(s.CONFIGS[0],b"changed")
        with self.assertRaises(ValueError): self.run_stage()
        self.assertFalse(self.output.exists())

    def test_alias_changed(self):
        alias=self.root/"bin/lhd"
        alias.unlink()
        alias.symlink_to("/usr/bin/other")
        with self.assertRaises(OSError): self.run_stage()
        self.assertFalse(self.output.exists())

    def test_source_recheck_failure(self):
        with self.assertRaises(ValueError):
            self.run_stage([self.report,self.report,dict(self.report,problems=["changed"])])
        self.assertFalse(self.output.exists())

    def test_root_rejected(self):
        with patch.object(s.os,"geteuid",return_value=0):
            with self.assertRaises(ValueError): s.stage(self.root,self.output)

    def test_no_replace_publication(self):
        src=self.parent/"candidate"
        src.mkdir()
        self.output.mkdir()
        with self.assertRaises(OSError): s.publish(src,self.output)
        self.assertTrue(src.is_dir())


if __name__=="__main__":
    unittest.main()
