"""Synthetic EXT4 original property-service evidence tests."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"build"))
import r800_qemu_ext4_property_service as a

D=[{"name":"system"},{"name":"vendor"},{"name":"runtime"}]
L={a.SERVICE:a.SERVICE_LABEL,a.FILE:a.LABEL}
CONSOLE = b" device=5:1 inode=42 filesystem=0:1\n"
import r800_bionic_behavior_contract as bionic
PROVIDER = bionic.PROVIDERS[2]
LOG=(a.disks.EXPECTED+b"r800-console: stage=kernel"+CONSOLE+b"r800-ext4-exec: system noexec=0\nr800-ext4-exec: vendor noexec=1\n"
     b"r800-ext4-exec: runtime noexec=0\n"+
     a.disks.PREFIX+b"PASS count=3 policy=not-loaded android=not-started\n"+
     a.RAM+b"\n"+a.START+b"\n"+
     b"".join(a.labels.PREFIX+b"path="+p.encode()+b" context="+v.encode()+b"\n" for p,v in L.items())+
     a.labels.PREFIX+b"PASS count=2 android=not-started\n"+
     a.EXEC+b"\n"+b"r800-console: stage=init"+CONSOLE+
     b"\n".join(a.MARKERS[:2])+b"\n"+b"r800-console: stage=client"+CONSOLE+
     b"\n".join(a.MARKERS[2:3]+bionic.markers(PROVIDER)+a.MARKERS[3:])+b"\n"+a.HEARTBEAT_PREFIX+b"00000001\n")

def images():
    old={"policy_sha256":"stock","verified_system_entries":{
        a.FILE[1:]:{"type":"regular","sha256":"client","context":"old"},
        a.SERVICE[1:]:{"type":"regular","sha256":"server","context":"old"}}}
    new={"policy_sha256":"fixture","service_fixture":True,
         "diagnostic_init_substitution":None,"experimental_linker_config_sha256":a.sha(a.CONFIG),
         "verified_system_entries":{
         a.FILE[1:]:{"type":"regular","sha256":"client","context":a.LABEL},
         a.SERVICE[1:]:{"type":"regular","sha256":"server","context":a.SERVICE_LABEL},
         "system/etc/ld.config.txt":{"sha256":a.sha(a.CONFIG)}}}
    return old,new

class Ext4ServiceTests(unittest.TestCase):
    def test_service_contract(self):
        result=a.inspect_console(LOG,D,L)
        self.assertTrue(result["property_service_started"])
        self.assertFalse(result["android_init_started"])
        self.assertFalse(result["stock_policy"])

    def test_missing_or_duplicate_bionic_diagnostics(self):
        for marker in bionic.markers(PROVIDER):
            for replacement in (b"", marker+b"\n"+marker):
                with self.subTest(marker=marker,replacement=replacement):
                    mutated=LOG.replace(marker,replacement)
                    with self.assertRaisesRegex(ValueError,"Missing or duplicate Bionic diagnostics"):
                        a.inspect_console(mutated,D,L)

    def test_fixture_not_stock(self):
        with self.assertRaisesRegex(ValueError,"fixture policy"):
            a.inspect_console(LOG.replace(a.START,a.labels.START),D,L)

    def test_runtime_exec_required(self):
        with self.assertRaisesRegex(ValueError,"execution flags"):
            a.inspect_console(LOG.replace(b"runtime noexec=0",b"runtime noexec=1"),D,L)

    def test_vendor_noexec_required(self):
        with self.assertRaisesRegex(ValueError,"execution flags"):
            a.inspect_console(LOG.replace(b"vendor noexec=1",b"vendor noexec=0"),D,L)

    def test_mac_status_distinct(self):
        with self.assertRaisesRegex(ValueError,"libinit/client sequence"):
            a.inspect_console(LOG.replace(b"status=0x0018",b"status=0x000b"),D,L)

    def test_changed_console_rejected(self):
        with self.assertRaisesRegex(ValueError,"stdout identity changed"):
            a.inspect_console(LOG.replace(b"stage=init"+CONSOLE,
                b"stage=init"+CONSOLE.replace(b"inode=42",b"inode=43")),D,L)

    def test_early_heartbeat(self):
        with self.assertRaisesRegex(ValueError,"Heartbeat before client"):
            a.inspect_console(LOG.replace(a.MARKERS[-1],a.HEARTBEAT_PREFIX+b"00000001\n"+a.MARKERS[-1]),D,L)

    def test_system_same_payloads(self):
        a.verify_system(*images())

    def test_modified_client_rejected(self):
        old,new=images()
        new["verified_system_entries"][a.FILE[1:]]["sha256"]="changed"
        with self.assertRaisesRegex(ValueError,"payloads changed"):
            a.verify_system(old,new)

    def test_wrong_config_rejected(self):
        old,new=images()
        new["verified_system_entries"]["system/etc/ld.config.txt"]["sha256"]="changed"
        with self.assertRaisesRegex(ValueError,"config content mismatch"):
            a.verify_system(old,new)

if __name__=="__main__":
    unittest.main()
