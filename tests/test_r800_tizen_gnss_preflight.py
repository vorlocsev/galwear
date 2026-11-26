"""Offline synthetic fixtures for GNSS chroot prerequisites."""
from pathlib import Path
import struct
import sys
import tempfile
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"build"))
from r800_tizen_gnss_preflight import check, DIRECTORIES, SOCKET, LAST, LTO
from test_android_linker_audit import fixture, classified_symbol_fixture


class GnssPreflightTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        for directory in DIRECTORIES:
            (self.root/directory.lstrip("/")).mkdir(parents=True)
        for name in ("/usr/bin/gpsd","/usr/bin/lhd"):
            self.put(name,fixture("arm"))
        data = classified_symbol_fixture("arm",section=1)
        strings = b"\0gps_get_hardware_interface\0"
        data[400:400+len(strings)] = strings
        struct.pack_into("<iI",data,232,10,len(strings))
        self.put("/usr/lib/libbrcm.so",data)

    def put(self,guest,raw):
        p = self.root/guest.lstrip("/")
        p.parent.mkdir(parents=True,exist_ok=True)
        p.write_bytes(raw)
        return p

    def test_static_only(self):
        report = check(self.root)
        self.assertEqual(report["status"],"TIZEN_GNSS_STATIC_ONLY")
        self.assertEqual(report["bridge_library"]["candidate_count"],1)
        self.assertFalse(report["hardware_interface_abi_verified"])
        self.assertFalse(report["gnss_fix_verified"])
        self.assertFalse(report["safe_to_flash"])

    def test_missing_export(self):
        self.put("/usr/lib/libbrcm.so",fixture("arm"))
        self.assertIn("BRIDGE_EXPORT_NOT_CONFIRMED",check(self.root)["problems"])

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

    def test_missing_daemon(self):
        (self.root/"usr/bin/lhd").unlink()
        self.assertIn("DEPENDENCY_CLOSURE_REVIEW",check(self.root)["problems"])


    def test_strict_page_review_bound_to_bridge(self):
        report=check(self.root,strict_pages=True)
        self.assertEqual(report["status"],"TIZEN_GNSS_STATIC_ONLY")
        self.assertTrue(report["strict_4k_page_review"])
        self.assertTrue(report["bridge_library"]["load_review"]["strict_4k_page_review"])
        self.assertFalse(report["safe_to_flash"])
        path=self.root/"usr/lib/libbrcm.so"
        data=bytearray(path.read_bytes())
        struct.pack_into("<H",data,44,3)
        struct.pack_into("<8I",data,116,1,0x400,0x1400,0,0,4,6,1)
        path.write_bytes(data)
        report=check(self.root,strict_pages=True)
        self.assertIn("DEPENDENCY_CLOSURE_REVIEW",report["problems"])
        self.assertIn("BRIDGE_LIBRARY_REJECTED",report["problems"])
        self.assertTrue(any("shared memory page" in p["reason"] for p in report["closure_problems"]))
        self.assertFalse(report["hardware_interface_abi_verified"])
        self.assertFalse(report["safe_to_flash"])


if __name__ == "__main__":
    unittest.main()
