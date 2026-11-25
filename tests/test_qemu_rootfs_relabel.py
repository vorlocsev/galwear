"""Synthetic expanded-rootfs relabel acceptance, not guest execution."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "build"))
import r800_qemu_rootfs_relabel as a

PATHS = ["/system", "/system/bin/init", "/dev/socket"]

def log(paths=PATHS):
    return (a.EXPECTED + a.START + b"\n" +
            b"".join(a.PREFIX + b"path=" + p.encode() +
                     b" context=u:object_r:system_file:s0\n" for p in paths) +
            a.PREFIX + f"PASS count={len(paths)} service=not-started\n".encode() +
            a.HEARTBEAT_PREFIX + b"00000001\n")

class RelabelTests(unittest.TestCase):
    def test_complete(self):
        report = a.inspect_console(log(), PATHS)
        self.assertEqual(report["relabel_count"], 3)
        self.assertFalse(report["property_service_started"])
        self.assertFalse(report["android_init_started"])

    def test_missing_or_duplicate_path(self):
        for paths in (PATHS[:-1], PATHS + PATHS[:1]):
            with self.assertRaisesRegex(ValueError, "Incomplete"):
                a.inspect_console(log(paths), PATHS)

    def test_reordered_path(self):
        with self.assertRaisesRegex(ValueError, "Unexpected path"):
            a.inspect_console(log(PATHS[::-1]), PATHS)

    def test_invalid_context(self):
        with self.assertRaisesRegex(ValueError, "Unexpected path"):
            a.inspect_console(log().replace(b"u:object_r:system_file:s0", b"invalid"), PATHS)

    def test_early_heartbeat(self):
        value = log().replace(a.START + b"\n", a.START+b"\n"+a.HEARTBEAT_PREFIX+b"00000001\n")
        with self.assertRaisesRegex(ValueError, "Heartbeat before"):
            a.inspect_console(value, PATHS)

    def test_unexpected_service(self):
        with self.assertRaisesRegex(ValueError, "Unexpected service"):
            a.inspect_console(log()+b"r800-property-service: started\n", PATHS)

    def test_archive_preserves_stock_init_and_replaces_pid1(self):
        entries = [("init", (0o100755, b"old-probe", 0, 0)),
                   ("system", (0o040755, b"", 0, 0)),
                   ("system/bin", (0o040755, b"", 0, 0)),
                   ("system/bin/init", (0o100755, b"stock-init", 0, 0))]
        raw, paths = a.make_archive(entries, b"relabel-probe", b"policy",
                                    {a.FILE_CONTEXTS[0]: b"file-contexts"})
        self.assertIn(b"stock-init", raw)
        self.assertIn(b"relabel-probe", raw)
        self.assertNotIn(b"old-probe", raw)
        self.assertIn("/dev/socket", paths)
        self.assertIn("/"+a.FILE_CONTEXTS[0], paths)
        self.assertNotIn("/galwear-policy", paths)

    def test_policy_collision(self):
        with self.assertRaisesRegex(ValueError, "existing policy"):
            a.make_archive([("galwear-policy", (0o100400, b"other", 0, 0))], b"init", b"policy", {})

if __name__ == "__main__":
    unittest.main()
