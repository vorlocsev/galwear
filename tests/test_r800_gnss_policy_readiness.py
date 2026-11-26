"""Bind binary policy candidates to the Android registration and context inventory."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"build"))
import r800_gnss_readiness as r


class PolicyReadinessTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root=Path(tmp.name)
        self.policy=self.root/"sepolicy"
        self.policy.write_bytes(b"synthetic policy")
        self.digest=hashlib.sha256(self.policy.read_bytes()).hexdigest()
        self.types_path=self.root/"types.json"
        self.types=dict(hal_domain="hal_gnss",bridge_domain="bridge",
                        oem_dir_type="oem_file",ipc_dir_type="ipc_dir",
                        socket_type="gps_socket",gnss_hwservice_type="gnss_hwservice")
        self.types_path.write_text(json.dumps(self.types))
        self.registration=r.outcome("android_registration","STATIC_PASS",
                         detail={"service_profile":"AOSP_CANDIDATE"})
        self.labels=self.root/"system/etc/selinux/plat_hwservice_contexts"
        self.labels.parent.mkdir(parents=True)
        self.labels.write_text("android.hardware.gnss::IGnss u:object_r:gnss_hwservice:s0\n")

    def check(self,change=None,code=0,mutate=False):
        profile="samsung" if self.registration["detail"]["service_profile"]=="SAMSUNG_J4_CANDIDATE" else "aosp"
        data={"schema":"r800-gnss-policy-candidates-v1","status":"STATIC_ALLOW_CANDIDATES_ONLY",
              "problems":[],"policy_sha256":self.digest,"profile":profile,"types":self.types,
              "effective_labels_verified":False,"constraints_verified":False,
              "domain_transitions_verified":False,"policy_loaded_verified":False,
              "runtime_enforcing_verified":False,"selinux_access_verified":False,"safe_to_flash":False}
        data.update(change or {})
        def launch(args,**kwargs):
            self.assertIn(str(self.policy),args)
            self.assertEqual("--samsung" in args,profile=="samsung")
            if mutate:
                self.labels.write_text("android.hardware.gnss::IGnss u:object_r:changed:s0\n")
            return subprocess.CompletedProcess(args,code,json.dumps(data).encode(),b"")
        with patch.object(r.subprocess,"run",side_effect=launch) as proc:
            gate=r.policy_gate(self.root,"/sepolicy",self.digest,self.types_path,self.registration)
        return gate,proc.call_count

    def test_aosp(self):
        gate,calls=self.check()
        self.assertEqual(calls,1)
        self.assertEqual(gate["status"],"STATIC_PASS",gate)
        self.assertEqual(gate["guest_policy"],"/sepolicy")

    def test_samsung(self):
        self.registration["detail"]["service_profile"]="SAMSUNG_J4_CANDIDATE"
        self.types["sec_hwservice_type"]="sec_gnss_hwservice"
        self.types_path.write_text(json.dumps(self.types))
        with self.labels.open("a") as f:
            f.write("vendor.samsung.hardware.gnss::ISecGnss u:object_r:sec_gnss_hwservice:s0\n")
        self.assertEqual(self.check()[0]["status"],"STATIC_PASS")

    def test_missing_registration(self):
        self.registration["status"]="REVIEW_REQUIRED"
        gate,calls=self.check()
        self.assertEqual(gate["status"],"BLOCKED")
        self.assertEqual(calls,0)

    def test_label_mismatch(self):
        self.types["gnss_hwservice_type"]="wrong"
        self.types_path.write_text(json.dumps(self.types))
        gate,calls=self.check()
        self.assertEqual(calls,0)
        self.assertIn("HWSERVICE_TYPE_MISMATCH:android.hardware.gnss::IGnss",gate["problems"])

    def test_wrong_digest(self):
        self.assertEqual(self.check({"policy_sha256":"0"*64})[0]["status"],"REVIEW_REQUIRED")

    def test_wrong_profile(self):
        self.assertEqual(self.check({"profile":"samsung"})[0]["status"],"REVIEW_REQUIRED")

    def test_wrong_types(self):
        self.assertEqual(self.check({"types":{}})[0]["status"],"REVIEW_REQUIRED")

    def test_runtime_claim_rejected(self):
        self.assertEqual(self.check({"selinux_access_verified":True})[0]["status"],"REVIEW_REQUIRED")

    def test_mutated_labels(self):
        self.assertEqual(self.check(mutate=True)[0]["status"],"ERROR")

    def test_partial_inputs(self):
        with patch.object(sys,"argv",["readiness","--selinux-policy","/sepolicy"]), \
             patch.object(r,"git_state",return_value=("a"*40,True)), \
             patch.object(r,"static_gate") as launch, patch("builtins.print") as output:
            self.assertEqual(r.main(),2)
            launch.assert_not_called()
            self.assertEqual(json.loads(output.call_args.args[0])["decision"],"REJECT_EVIDENCE")

    def test_static_never_promotes_runtime(self):
        gate,_=self.check()
        report=r.summarize("a"*40,True,[gate])
        self.assertIn("selinux_enforcing_access",report["blockers"])
        self.assertFalse(report["safe_to_flash"])
        self.assertFalse(report["daemon_build_authorized"])


if __name__=="__main__":
    unittest.main()
