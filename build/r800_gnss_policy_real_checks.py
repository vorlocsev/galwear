#!/usr/bin/env python3
"""Mandatory real-tool integration on generated SELinux CIL, never load policy."""
import hashlib
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from r800_gnss_policy import inspect

CIL = """(handleunknown deny)
(mls false)
(class dir (search))
(class sock_file (write))
(class unix_stream_socket (connectto))
(class hwservice_manager (add))
(classorder (dir sock_file unix_stream_socket hwservice_manager))
(sid kernel)
(sidorder (kernel))
(user system_u)
(role object_r)
(type hal_gnss)
(type bridge)
(type oem_file)
(type ipc_dir)
(type gps_socket)
(type gnss_hwservice)
(type sec_gnss_hwservice)
(roletype object_r hal_gnss)
(userrole system_u object_r)
(sensitivity s0)
(sensitivityorder (s0))
(level low (s0))
(levelrange low_low (low low))
(userlevel system_u low)
(userrange system_u low_low)
(sidcontext kernel (system_u object_r hal_gnss low_low))
(typeattribute hal_clients)
(typeattributeset hal_clients (hal_gnss))
(allow hal_clients oem_file (dir (search)))
(allow hal_gnss ipc_dir (dir (search)))
(allow hal_gnss gps_socket (sock_file (write)))
(allow hal_gnss bridge (unix_stream_socket (connectto)))
(allow hal_gnss gnss_hwservice (hwservice_manager (add)))
(allow hal_gnss sec_gnss_hwservice (hwservice_manager (add)))
(boolean feature true)
"""
CONNECT = "(allow hal_gnss bridge (unix_stream_socket (connectto)))"
SEC_ADD = "(allow hal_gnss sec_gnss_hwservice (hwservice_manager (add)))"


class RealPolicyTests(unittest.TestCase):
    def setUp(self):
        temp=tempfile.TemporaryDirectory(prefix="r800-cil-fixture-")
        self.addCleanup(temp.cleanup)
        self.root=Path(temp.name)
        self.types=dict(hal_domain="hal_gnss",bridge_domain="bridge",
                        oem_dir_type="oem_file",ipc_dir_type="ipc_dir",
                        socket_type="gps_socket",gnss_hwservice_type="gnss_hwservice")

    def compile(self,cil=CIL):
        source=self.root/"fixture.cil"
        policy=self.root/"fixture.policy"
        source.write_text(cil)
        subprocess.run(["secilc","-c","30","-o",str(policy),"-f",str(self.root/"contexts"),
                        str(source)],check=True,timeout=30)
        return policy,hashlib.sha256(policy.read_bytes()).hexdigest()

    def audit(self,cil=CIL,samsung=False):
        policy,digest=self.compile(cil)
        result=inspect(policy,digest,self.types,samsung)
        self.assertEqual(hashlib.sha256(policy.read_bytes()).hexdigest(),digest)
        for key in ("effective_labels_verified","constraints_verified",
                    "domain_transitions_verified","policy_loaded_verified",
                    "runtime_enforcing_verified","selinux_access_verified","safe_to_flash"):
            self.assertIs(result[key],False)
        return result

    def test_aosp_real_allow(self):
        result=self.audit()
        self.assertEqual(result["status"],"STATIC_ALLOW_CANDIDATES_ONLY",result)
        self.assertEqual(len(result["checks"]),5)
        self.assertTrue(all(c["unconditional_allow_candidate"] for c in result["checks"]))

    def test_samsung_real_allow(self):
        self.types["sec_hwservice_type"]="sec_gnss_hwservice"
        result=self.audit(samsung=True)
        self.assertEqual(result["status"],"STATIC_ALLOW_CANDIDATES_ONLY",result)
        self.assertEqual(len(result["checks"]),6)

    def test_missing_connect(self):
        result=self.audit(CIL.replace(CONNECT,""))
        self.assertEqual(result["problems"],[
            "ALLOW_NOT_CONFIRMED:hal_gnss:bridge:unix_stream_socket:connectto"])

    def test_conditional_connect(self):
        conditional="(booleanif feature (true "+CONNECT+"))"
        result=self.audit(CIL.replace(CONNECT,conditional))
        self.assertEqual(result["problems"],[
            "ALLOW_NOT_CONFIRMED:hal_gnss:bridge:unix_stream_socket:connectto"])

    def test_missing_samsung_add(self):
        self.types["sec_hwservice_type"]="sec_gnss_hwservice"
        result=self.audit(CIL.replace(SEC_ADD,""),True)
        self.assertEqual(result["problems"],[
            "ALLOW_NOT_CONFIRMED:hal_gnss:sec_gnss_hwservice:hwservice_manager:add"])

    def test_nonexistent_type(self):
        self.types["bridge_domain"]="unknown_domain"
        result=self.audit()
        self.assertIn("CONCRETE_TYPE_NOT_CONFIRMED:unknown_domain",result["problems"])
        self.assertEqual(result["checks"],[])

    def test_wrong_digest(self):
        policy,_=self.compile()
        with self.assertRaisesRegex(ValueError,"SHA-256"):
            inspect(policy,"0"*64,self.types)


if __name__=="__main__":
    for tool in ("secilc","seinfo","sesearch"):
        if not shutil.which(tool):
            raise SystemExit("Required real SELinux tool missing: "+tool)
    suite=unittest.defaultTestLoader.loadTestsFromTestCase(RealPolicyTests)
    result=unittest.TextTestRunner(verbosity=2).run(suite)
    if not result.wasSuccessful() or result.testsRun!=7 or result.skipped:
        raise SystemExit(1)
    print("GPS_SELINUX_SYNTHETIC_BINARY_POLICY=PASS")
    print("ORIGINAL_ANDROID_POLICY_VERIFIED=false")
    print("SELINUX_RUNTIME_ACCESS_VERIFIED=false")
    print("safe_to_flash=false")
