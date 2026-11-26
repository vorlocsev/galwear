"""Fresh donor report validation with synthetic evidence only."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"build"))
import r800_gnss_donor_gate as gate
import r800_gnss_readiness as readiness

SHA="a"*40
IMAGE="b"*64


class DonorGateTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root=Path(temp.name)
        self.out=self.root/"evidence"
        self.out.mkdir()
        raw=b"synthetic linker log"
        (self.out/"link.log").write_bytes(raw)
        self.hashes={n:hashlib.sha256(n.encode()).hexdigest() for n in gate.DONORS}
        self.report={"schema":"r800-tizen-glibc-check-v1","source_sha":SHA,
            "image_sha256":IMAGE,"status":"STATIC_DONOR_LINK_ONLY",
            "donor_authenticity_verified":False,"gnss_runtime_verified":False,"safe_to_flash":False,
            "gates":{"extraction":{"status":"PASS","donor_sha256":self.hashes,
                "detail":{"image_sha256":IMAGE,"snapshot_verified":True,"profile":"gps-glibc",
                "missing_or_ambiguous":[],"safe_to_flash":False,
                "files":{"tizen/"+n:{"status":"EXTRACTED","sha256":d}
                         for n,d in self.hashes.items()}}},
                "elf":{"status":"STATIC_PASS"},"qemu":{"status":"NOT_TESTED"},
                "link":{"status":"STATIC_PASS","exit_code":0,"log_file":"link.log",
                "log_sha256":hashlib.sha256(raw).hexdigest(),
                "detail":{"status":"STATIC_GLIBC_CLOSURE_ONLY","static_closure_pass":True,
                          "problems":[],"donor_sha256":dict(self.hashes),"safe_to_flash":False,
                          "sha256":"c"*64}}}}

    def validate(self):
        return gate.validate(self.report,SHA,IMAGE,self.out)

    def test_complete(self):
        self.assertEqual(self.validate(),self.hashes)

    def test_wrong_sha(self):
        self.report["source_sha"]="d"*40
        with self.assertRaises(ValueError): self.validate()

    def test_wrong_image(self):
        self.report["image_sha256"]="d"*64
        with self.assertRaises(ValueError): self.validate()

    def test_modified_log(self):
        (self.out/"link.log").write_bytes(b"changed")
        with self.assertRaises(ValueError): self.validate()

    def test_wrong_link_hash(self):
        self.report["gates"]["link"]["detail"]["donor_sha256"]={}
        with self.assertRaises(ValueError): self.validate()

    def test_runtime_claim(self):
        self.report["gnss_runtime_verified"]=True
        with self.assertRaises(ValueError): self.validate()

    def test_unexpected_qemu(self):
        (self.out/"qemu.log").write_text("unexpected")
        with self.assertRaises(ValueError): self.validate()

    def test_stale_output(self):
        with patch.object(gate.subprocess,"run") as launch:
            with self.assertRaises(ValueError):
                gate.run(self.root/"checkout",SHA,self.root/"image",IMAGE,self.root/"ndk",self.out)
            launch.assert_not_called()

    def test_fresh_subprocess(self):
        output=self.root/"new"
        def launch(args,**kw):
            self.assertNotIn("--run-qemu",args)
            output.mkdir()
            (output/"link.log").write_bytes((self.out/"link.log").read_bytes())
            (output/"report.json").write_text(json.dumps(self.report))
            return subprocess.CompletedProcess(args,0,json.dumps(self.report).encode(),b"")
        with patch.object(gate.subprocess,"run",side_effect=launch):
            result=gate.run(self.root/"checkout",SHA,self.root/"image",IMAGE,self.root/"ndk",output)
        self.assertEqual(result["status"],"STATIC_PASS")

    def test_no_runtime_promotion(self):
        report=readiness.summarize(SHA,True,[readiness.outcome("donor_image_link","STATIC_PASS")])
        self.assertIn("donor_glibc_qemu",report["blockers"])
        self.assertIn("physical_gnss_fix",report["blockers"])
        self.assertFalse(report["safe_to_flash"])


if __name__=="__main__":
    unittest.main()
