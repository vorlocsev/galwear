"""Synthetic policy header and mocked SETools queries, no policy loading."""
import hashlib
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"build"))
import r800_gnss_policy as p


class PolicyTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.policy=Path(temp.name)/"policy"
        raw=struct.pack("<II",0xf97cff8c,8)+b"SE Linux"+struct.pack("<IIII",30,1,8,7)
        self.policy.write_bytes(raw)
        self.sha=hashlib.sha256(raw).hexdigest()
        self.types=dict(hal_domain="hal_gnss",bridge_domain="bridge",
                        oem_dir_type="oem_file",ipc_dir_type="ipc_dir",
                        socket_type="gps_socket",gnss_hwservice_type="gnss_hwservice")
    def inspect(self, mode="allow", samsung=False):
        def query(tool,args):
            if tool=="seinfo":
                return "Types: 1\n   "+args[1]+"\n" if mode!="missing_type" else "Types: 0\n"
            self.assertEqual(tool,"sesearch")
            self.assertNotEqual(Path(args[-1]),self.policy)
            self.assertEqual(hashlib.sha256(Path(args[-1]).read_bytes()).hexdigest(),self.sha)
            src,dst,cls,perm=(args[args.index(flag)+1] for flag in ("-s","-t","-c","-p"))
            rule=f"allow {src} {dst}:{cls} {{ {perm} }};"
            if mode=="conditional":
                return rule+" [ feature ]:True\n"
            if mode=="denied":
                return ""
            return rule+"\n"
        with patch.object(p.shutil,"which",side_effect=lambda name:name), \
             patch.object(p,"query",side_effect=query):
            report=p.inspect(self.policy,self.sha,self.types,samsung)
        self.assertFalse(report["selinux_access_verified"])
        self.assertFalse(report["safe_to_flash"])
        return report
    def test_aosp(self):
        r=self.inspect()
        self.assertEqual(r["status"],"STATIC_ALLOW_CANDIDATES_ONLY")
        self.assertEqual(len(r["checks"]),5)
    def test_samsung(self):
        self.types["sec_hwservice_type"]="sec_gnss_hwservice"
        self.assertEqual(len(self.inspect(samsung=True)["checks"]),6)
    def test_missing_samsung_type(self):
        with self.assertRaises(ValueError): self.inspect(samsung=True)
    def test_conditional_only(self):
        self.assertEqual(self.inspect("conditional")["status"],"REVIEW_REQUIRED")
    def test_absent_allow(self):
        self.assertEqual(len(self.inspect("denied")["problems"]),5)
    def test_missing_type(self):
        self.assertFalse(self.inspect("missing_type")["checks"])
    def test_wrong_hash(self):
        with self.assertRaisesRegex(ValueError,"SHA-256"):
            p.inspect(self.policy,"0"*64,self.types)
    def test_invalid_type(self):
        self.types["hal_domain"]="--allow"
        with self.assertRaises(ValueError): self.inspect()
    def test_tool_missing(self):
        with patch.object(p.shutil,"which",return_value=None):
            with self.assertRaisesRegex(ValueError,"SETools"):
                p.inspect(self.policy,self.sha,self.types)
    def test_rule_parser(self):
        self.assertTrue(p.matching_rule("allow attr target:sock_file { read write };","sock_file","write"))
        self.assertFalse(p.matching_rule("allow attr target:sock_file read;","sock_file","write"))
        self.assertFalse(p.matching_rule("allow attr target:dir write;","sock_file","write"))

if __name__=="__main__":
    unittest.main()
