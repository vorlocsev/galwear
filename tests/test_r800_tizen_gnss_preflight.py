"""Offline synthetic fixtures for GNSS chroot prerequisites."""
from pathlib import Path
import struct
import sys
import tempfile
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"build"))
from r800_tizen_gnss_preflight import check, closure_review, DIRECTORIES, SOCKET, LAST, LTO, TARGETS
from test_android_linker_audit import fixture, classified_symbol_fixture


class GnssPreflightTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        for directory in DIRECTORIES:
            (self.root/directory.lstrip("/")).mkdir(parents=True)
        for name in ("/usr/bin/gpsd","/usr/bin/lhd"):
            self.put(name,self.bridge_fixture(name=b"daemon_symbol"))
        self.put("/usr/lib/libbrcm.so", self.bridge_fixture())

    @staticmethod
    def bridge_fixture(name=b"gps_get_hardware_interface", flags=0x05000200, binding=1):
        data = classified_symbol_fixture("arm", section=1, binding=binding)
        struct.pack_into("<I", data, 36, flags)
        strings = b"\0" + name + b"\0"
        data[400:400+len(strings)] = strings
        struct.pack_into("<iI", data, 232, 10, len(strings))
        return data

    def put(self,guest,raw):
        p = self.root/guest.lstrip("/")
        p.parent.mkdir(parents=True,exist_ok=True)
        p.write_bytes(raw)
        return p

    def test_static_only(self):
        report = check(self.root)
        self.assertEqual(report["status"],"TIZEN_GNSS_STATIC_ONLY")
        self.assertEqual(report["bridge_library"]["candidate_count"],1)
        self.assertEqual(set(report["dependency_evidence"]["symbol_candidates"]["targets"]),set(TARGETS))
        self.assertFalse(report["dependency_evidence"]["symbol_resolution_verified"])
        self.assertFalse(report["hardware_interface_abi_verified"])
        self.assertFalse(report["gnss_fix_verified"])
        self.assertFalse(report["safe_to_flash"])

    def test_missing_export(self):
        self.put("/usr/lib/libbrcm.so", self.bridge_fixture(name=b"other_symbol"))
        self.assertIn("BRIDGE_EXPORT_NOT_CONFIRMED", check(self.root)["problems"])

    def test_missing_symbol_inventory(self):
        data = fixture("arm")
        struct.pack_into("<I", data, 36, 0x05000200)
        self.put("/usr/lib/libbrcm.so", data)
        self.assertIn("BRIDGE_LIBRARY_REJECTED", check(self.root)["problems"])

    def test_hard_float_rejected(self):
        self.put("/usr/lib/libbrcm.so", self.bridge_fixture(flags=0x05000400))
        report = check(self.root)
        self.assertIn("BRIDGE_LIBRARY_REJECTED", report["problems"])
        self.assertFalse(report["safe_to_flash"])

    def test_weak_export_rejected(self):
        self.put("/usr/lib/libbrcm.so", self.bridge_fixture(binding=2))
        self.assertIn("BRIDGE_EXPORT_NOT_CONFIRMED", check(self.root)["problems"])

    def test_occupied_socket_path(self):
        self.put(SOCKET,b"not a socket")
        self.assertIn("SOCKET_PATH_ALREADY_OCCUPIED_OR_UNSAFE",check(self.root)["problems"])

    def test_symlink_runtime_directory(self):
        p = self.root/"opt/usr/r800dev"
        p.rmdir()
        p.symlink_to("/tmp",target_is_directory=True)
        report = check(self.root)
        self.assertEqual(report["directories"]["/opt/usr/r800dev"]["status"],"REJECTED_SYMLINK")
        self.assertFalse(report["safe_to_flash"])

    def test_optional_metadata_not_contents(self):
        self.put(LAST,b"private synthetic data")
        self.put(LTO,b"synthetic orbit data")
        report = check(self.root)
        self.assertEqual(report["optional_metadata"][LAST]["kind"],"regular")
        self.assertNotIn("private synthetic data",str(report))
        self.assertNotIn("synthetic orbit data",str(report))

    def test_daemon_missing_eabi(self):
        self.put("/usr/bin/gpsd",self.bridge_fixture(flags=0))
        self.assertIn("DEPENDENCY_ARM_ABI_REVIEW:/usr/bin/gpsd",check(self.root)["problems"])

    def test_daemon_incomplete_symbols(self):
        data=fixture("arm")
        struct.pack_into("<I",data,36,0x05000200)
        self.put("/usr/bin/gpsd",data)
        report=check(self.root)
        self.assertIn("DEPENDENCY_SYMBOL_INVENTORY_REVIEW:/usr/bin/gpsd",report["problems"])
        self.assertIn("DEPENDENCY_SYMBOL_SCOPE_INCOMPLETE:/usr/bin/gpsd",report["problems"])

    def test_strong_import_cannot_use_unrelated_daemon(self):
        data=classified_symbol_fixture("arm",section=0)
        struct.pack_into("<I",data,36,0x05000200)
        self.put("/usr/bin/gpsd",data)
        self.put("/usr/bin/lhd",self.bridge_fixture(name=b"symbol"))
        report=check(self.root)
        self.assertIn("DEPENDENCY_STRONG_IMPORT_REVIEW:/usr/bin/gpsd",report["problems"])
        self.assertEqual(report["status"],"TIZEN_GNSS_REVIEW_REQUIRED")

    def test_weak_import_remains_candidate_only(self):
        data=classified_symbol_fixture("arm",binding=2,section=0)
        struct.pack_into("<I",data,36,0x05000200)
        self.put("/usr/bin/gpsd",data)
        report=check(self.root)
        self.assertEqual(report["status"],"TIZEN_GNSS_STATIC_ONLY")
        self.assertEqual(len(report["dependency_evidence"]["symbol_candidates"]["targets"]
                             ["/usr/bin/gpsd"]["missing_weak"]),1)
        self.assertFalse(report["gnss_fix_verified"])

    def test_review_budget_and_missing_target(self):
        report=check(self.root)["dependency_evidence"]
        report["symbol_candidates"]["limit_exceeded"]=True
        del report["symbol_candidates"]["targets"]["/usr/bin/gpsd"]
        problems=closure_review(report)
        self.assertIn("DEPENDENCY_SYMBOL_BUDGET_EXCEEDED",problems)
        self.assertIn("DEPENDENCY_TARGET_SCOPE_MISSING:/usr/bin/gpsd",problems)

    def test_relocation_review_propagated(self):
        report=check(self.root)["dependency_evidence"]
        report["relocation_review_objects"]=["/usr/bin/lhd"]
        self.assertIn("DEPENDENCY_RELOCATION_REVIEW",closure_review(report))

    def test_ambiguous_symbol_review(self):
        report=check(self.root)["dependency_evidence"]
        report["symbol_candidates"]["targets"]["/usr/bin/lhd"]["ambiguous"]=[{"name":"symbol"}]
        self.assertIn("DEPENDENCY_AMBIGUOUS_IMPORT_REVIEW:/usr/bin/lhd",closure_review(report))

    def test_missing_daemon(self):
        (self.root/"usr/bin/lhd").unlink()
        self.assertIn("DEPENDENCY_CLOSURE_REVIEW",check(self.root)["problems"])


if __name__ == "__main__":
    unittest.main()
