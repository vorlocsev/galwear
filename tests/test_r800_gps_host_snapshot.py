"""Synthetic captured host closure tests; no synthetic ELF is executed."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/"build"))
from r800_gps_host_elf import audit, TOOLS, LOADER
from r800_gps_host_snapshot import plan, snapshot, check_listing
from test_r800_gps_host_elf import fixture


class HostSnapshotTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.libs = self.root / "lib"
        self.libs.mkdir()
        self.loader = self.libs / "loader"
        self.loader.write_bytes(fixture())
        (self.libs / "liba.so").write_bytes(fixture(["libb.so"]))
        (self.libs / "libb.so").write_bytes(fixture())
        tools = {}
        for name in TOOLS:
            tools[name] = self.root / name
            tools[name].write_bytes(fixture(["liba.so"], interpreter=True))
        self.report = audit(tools, directories=(self.libs,), loader=self.loader)
        self.staging = self.root / "stage"
        self.staging.mkdir()
        self.host = self.staging / "host"

    def test_snapshot_and_mutations(self):
        with patch("r800_gps_host_snapshot.reject_preload"):
            evidence = snapshot(self.staging, self.report, create=True)
            self.assertEqual(evidence, snapshot(self.staging, self.report))
            self.assertFalse(evidence["host_isolated"])
            self.assertFalse(evidence["runtime_verified"])
            path = self.host / "lib/liba.so"
            path.chmod(0o600)
            with self.assertRaisesRegex(ValueError, "snapshot changed"):
                snapshot(self.staging, self.report)
            path.chmod(0o400)
            (self.host/"lib/extra.so").write_bytes(b"unexpected")
            with self.assertRaisesRegex(ValueError, "Unexpected host library"):
                snapshot(self.staging, self.report)

    def test_provider_changed_before_capture(self):
        (self.libs/"libb.so").write_bytes(b"changed")
        with patch("r800_gps_host_snapshot.reject_preload"), self.assertRaisesRegex(ValueError, "provider changed"):
            snapshot(self.staging, self.report, create=True)

    def test_incomplete_plan(self):
        changed = dict(self.report, problems=[{"reason":"MISSING"}])
        with self.assertRaisesRegex(ValueError, "closure requires review"):
            plan(changed)

    def listing(self):
        return "\n".join(("linux-vdso.so.1 (0x1234)",
                           "liba.so => " + str(self.host/"lib/liba.so") + " (0x2345)",
                           "libb.so => " + str(self.host/"lib/libb.so") + " (0x3456)",
                           LOADER + " => " + str(self.host/"loader") + " (0x4567)"))

    def test_listing_rejects_escape_and_missing_member(self):
        listing = self.listing()
        check_listing(listing, self.staging, self.report, "clang")
        with self.assertRaisesRegex(ValueError, "escaped"):
            check_listing(listing.replace(str(self.host/"lib/libb.so"), "/usr/lib/libb.so"),
                          self.staging, self.report, "clang")
        with self.assertRaisesRegex(ValueError, "Incomplete"):
            check_listing("\n".join(line for line in listing.splitlines() if not line.startswith("libb.so")),
                          self.staging, self.report, "clang")


if __name__ == "__main__":
    unittest.main()
