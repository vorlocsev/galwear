import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"build"))
import r800_gnss_readiness as r

class ReadinessTests(unittest.TestCase):
    def static(self,code,data):
        result=subprocess.CompletedProcess([],code,json.dumps(data).encode(),b"")
        with patch.object(r.subprocess,"run",return_value=result):
            return r.static_gate("link","unused.py",["x"],"STATIC_ONLY")
    def test_missing_inputs(self):
        self.assertEqual(r.static_gate("link","unused",None,"STATIC_ONLY")["status"],"NOT_TESTED")
    def test_static_only(self):
        self.assertEqual(self.static(0,{"status":"STATIC_ONLY","problems":[],"safe_to_flash":False})["status"],"STATIC_PASS")
    def test_failure(self):
        self.assertEqual(self.static(2,{"status":"STATIC_ONLY","problems":[],"safe_to_flash":False})["status"],"REVIEW_REQUIRED")
    def test_missing_problems(self):
        self.assertEqual(self.static(0,{"status":"STATIC_ONLY","safe_to_flash":False})["status"],"ERROR")
    def test_false_flash_marker(self):
        self.assertEqual(self.static(0,{"status":"STATIC_ONLY","problems":[],"safe_to_flash":True})["status"],"ERROR")
    def test_dirty(self):
        self.assertEqual(r.offline_gate(True,"a"*40,False)["status"],"BLOCKED")
    def test_markers(self):
        sha="a"*40
        lines=["SOURCE_SHA="+sha,"GPS_OFFLINE_COMPILE_GATE=PASS","DONOR_LINK_VERIFIED=false",
               "QEMU_RUNTIME_VERIFIED=false","GNSS_RUNTIME_VERIFIED=false","safe_to_flash=false"]
        with patch.object(r,"git_state",return_value=(sha,True)):
            for extra,expected in (([],"PASS"),(["GPS_OFFLINE_COMPILE_GATE=PASS"],"FAILED")):
                result=subprocess.CompletedProcess([],0,"\n".join(lines+extra).encode(),b"")
                with patch.object(r.subprocess,"run",return_value=result):
                    self.assertEqual(r.offline_gate(True,sha,True)["status"],expected)
    def test_hold_even_when_static_passes(self):
        report=r.summarize("a"*40,True,[r.outcome("link","STATIC_PASS")])
        self.assertFalse(report["safe_to_flash"])
        self.assertFalse(report["daemon_build_authorized"])
        self.assertFalse(report["ci_verified"])
        self.assertEqual(report["decision"],"HOLD_RUNTIME_UNVERIFIED")
        self.assertEqual(set(report["blockers"]),set(r.RUNTIME))

if __name__=="__main__":
    unittest.main()
