"""Synthetic thread/event acceptance; no actual guest boot implied."""
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"build"))
import r800_qemu_thread_event as a

LOG=a.EXPECTED.rstrip(b"\n")+b"\n"+b"\n".join(a.MARKERS)+b"\n"+a.HEARTBEAT_PREFIX+b"00000001\n"

class ThreadEventTests(unittest.TestCase):
    def test_complete(self):
        result=a.inspect_console(LOG)
        self.assertTrue(result["epoll_eventfd_reported"])
        self.assertTrue(result["futex_eagain_timeout_wake_reported"])
        self.assertFalse(result["bionic_tested"])
        self.assertFalse(result["safe_to_flash"])

    def test_missing_duplicate_or_changed_marker(self):
        for marker in a.MARKERS:
            for replacement in (b"",marker+b"\n"+marker,marker+b" FAIL"):
                with self.assertRaises(ValueError):
                    a.inspect_console(LOG.replace(marker,replacement))

    def test_early_heartbeat(self):
        with self.assertRaisesRegex(ValueError,"Heartbeat before"):
            a.inspect_console(LOG.replace(a.MARKERS[-1],a.HEARTBEAT_PREFIX+b"00000001\n"+a.MARKERS[-1]))

    def test_android_marker_rejected(self):
        with self.assertRaisesRegex(ValueError,"Unexpected Android"):
            a.inspect_console(LOG+b"r800-bionic: memory=PASS\n")

    def test_exact_config_contract(self):
        config={"status":"VIRT_CONFIG_STATIC_ONLY","profile":"block",
                "virtio_block_profile":True,"compiled_kernel_sha256":"kernel",
                "property_event_loop_configured":True,"safe_to_flash":False,
                "required":sorted(a.REQUIRED)}
        a.verify_config(config,"kernel")
        for key in a.REQUIRED:
            with self.assertRaises(ValueError):
                a.verify_config({**config,"required":sorted(a.REQUIRED-{key})},"kernel")
        for key,value in (("profile","property"),("compiled_kernel_sha256","other"),
                          ("property_event_loop_configured",False),("safe_to_flash",True)):
            with self.assertRaises(ValueError):
                a.verify_config({**config,key:value},"kernel")

if __name__=="__main__":
    unittest.main()
