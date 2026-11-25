import sys
from pathlib import Path
import tempfile
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"build"))
from r800_gnss_ipc_layout import identity, resolve_id, mapping, account_candidates, SERVICE

class IdentityTests(unittest.TestCase):
    def setUp(self):
        self.s={"name":"vendor.gnss","source":"/vendor/etc/init/gnss.rc",
                "executable":SERVICE,"options":[{"name":"user","args":["gps"]},
                {"name":"group","args":["gps","system"]}]}
        self.i={"gnss_services":[self.s],"errors":[],"unresolved_imports":[],
                "duplicate_services":[]}
        self.u={"gps":{1234}}
        self.g={"gps":{2345},"system":{1000}}
    def check(self):
        return identity(self.i,self.u,self.g)
    def test_named(self):
        self.assertEqual(self.check()["uid_candidate"],1234)
        self.assertEqual(self.check()["primary_gid_candidate"],2345)
    def test_numeric(self):
        self.assertEqual(resolve_id("1234",{}),1234)
    def test_root_rejected(self):
        for name,db in (("0",{}),("root",{"root":{0}})):
            with self.assertRaises(ValueError): resolve_id(name,db)
    def test_conflicting(self):
        self.u["gps"].add(5678)
        with self.assertRaises(ValueError): self.check()
    def test_missing_user(self):
        self.s["options"].pop(0)
        with self.assertRaises(ValueError): self.check()
    def test_duplicate_service(self):
        self.i["duplicate_services"]=[{"name":"vendor.gnss"}]
        with self.assertRaises(ValueError): self.check()
    def test_unresolved_import(self):
        self.i["unresolved_imports"]=["unknown"]
        with self.assertRaises(ValueError): self.check()
    def test_account_conflict(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            for part,uid in (("system",1234),("vendor",2345)):
                p=root/part/"etc/passwd"
                p.parent.mkdir(parents=True)
                p.write_text(f"gps:x:{uid}:1234::/:/bin/false\n")
            users,hashes=account_candidates(root,"passwd")
            self.assertEqual(users["gps"],{1234,2345})
            self.assertEqual(len(hashes),2)
    def test_distinct_or_untrusted_directories_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            a,t=Path(tmp)/"android",Path(tmp)/"tizen"
            (a/"oem/r800dev").mkdir(parents=True)
            (t/"opt/usr/r800dev").mkdir(parents=True)
            with self.assertRaises(ValueError): mapping(a,t)
    def test_symlink_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            a,t=Path(tmp)/"android",Path(tmp)/"tizen"
            a.mkdir()
            (t/"opt/usr/r800dev").mkdir(parents=True)
            (a/"oem").symlink_to(t/"opt/usr")
            with self.assertRaises(ValueError): mapping(a,t)

if __name__=="__main__":
    unittest.main()
