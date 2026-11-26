import sys
from pathlib import Path
import tempfile
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"build"))
from r800_gnss_ipc_layout import (identity, resolve_id, mapping, account_candidates, SERVICE,
    SEC_SERVICE, context_candidates, label_evidence, label_review)

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
    def test_samsung_identity(self):
        self.s["executable"]=SEC_SERVICE
        self.assertEqual(self.check()["executable"],SEC_SERVICE)
        self.assertEqual(self.check()["uid_candidate"],1234)
    def test_competing_service_rejected(self):
        self.i["gnss_services"].append(dict(self.s,name="sec",executable=SEC_SERVICE))
        with self.assertRaises(ValueError): self.check()
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

class ContextTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
    def put(self,part,kind,text):
        prefix="plat" if part=="system" else part
        p=self.root/part/"etc/selinux"/(prefix+"_"+kind)
        p.parent.mkdir(parents=True,exist_ok=True)
        p.write_text(text)
    def test_samsung_both_contexts(self):
        self.put("vendor","hwservice_contexts",
                 "android.hardware.gnss::IGnss u:object_r:hal_gnss_hwservice:s0\n"
                 "vendor.samsung.hardware.gnss::ISecGnss u:object_r:hal_sec_gnss_hwservice:s0\n")
        evidence=label_evidence(self.root)
        self.assertEqual(label_review(evidence,SEC_SERVICE),[])
    def test_missing_samsung_context(self):
        self.put("system","hwservice_contexts",
                 "android.hardware.gnss::IGnss u:object_r:hal_gnss_hwservice:s0\n")
        evidence=label_evidence(self.root)
        self.assertEqual(label_review(evidence,SERVICE),[])
        self.assertEqual(label_review(evidence,SEC_SERVICE),
                         ["HWSERVICE_CONTEXT_NOT_IDENTIFIED:vendor.samsung.hardware.gnss::ISecGnss"])
    def test_conflicting_contexts(self):
        for part,typ in (("system","hal_gnss_hwservice"),("vendor","other_hwservice")):
            self.put(part,"hwservice_contexts","android.hardware.gnss::IGnss u:object_r:"+typ+":s0\n")
        self.assertIn("HWSERVICE_CONTEXT_CONFLICT:android.hardware.gnss::IGnss",
                      label_review(label_evidence(self.root),SERVICE))
    def test_file_context_candidates_only(self):
        raw=br"/vendor/bin/hw/vendor\.samsung\.hardware\.gnss@1\.0-service u:object_r:hal_gnss_default_exec:s0"+b"\n"
        records=context_candidates(raw,"file_contexts")
        self.assertEqual(len(records),1)
        self.assertEqual(records[0]["line"],1)
        self.assertEqual(records[0]["context"],"u:object_r:hal_gnss_default_exec:s0")
    def test_malformed_context(self):
        with self.assertRaises(ValueError):
            context_candidates(b"android.hardware.gnss::IGnss bad\n","hwservice_contexts")

if __name__=="__main__":
    unittest.main()
