"""Synthetic captured host closure tests; no synthetic ELF is executed."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/"build"))
from r800_gps_host_elf import audit, TOOLS, LOADER
from r800_gps_host_snapshot import plan, snapshot, check_listing, WRAPPER
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


class RealLoaderWrapperTests(unittest.TestCase):
    def test_real_glibc_wrapper_path_and_pid(self):
        import platform
        import shutil
        import subprocess
        loader = Path(LOADER)
        libc = Path("/lib/x86_64-linux-gnu/libc.so.6")
        program = Path("/bin/true")
        if (platform.system() != "Linux" or platform.machine() != "x86_64"
                or platform.libc_ver()[0] != "glibc"
                or not all(p.is_file() for p in (loader, libc, program))
                or Path("/etc/ld.so.preload").exists()):
            self.skipTest("Requires standard x86-64 glibc host without preload")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root/"host/lib").mkdir(parents=True)
            (root/"tools").mkdir()
            (root/"host-trace").mkdir()
            shutil.copyfile(loader, root/"host/loader")
            (root/"host/loader").chmod(0o500)
            shutil.copyfile(libc, root/"host/lib/libc.so.6")
            shutil.copyfile(program, root/"tools/ld.lld")
            (root/"tools/ld.lld").chmod(0o500)
            wrapper = root/"host/ld.lld"
            wrapper.write_bytes(WRAPPER)
            wrapper.chmod(0o500)
            result = subprocess.run([str(wrapper)], env={
                "PATH": "/usr/bin:/bin", "LC_ALL": "C", "TZ": "UTC",
                "LD_DEBUG": "files,libs",
                "LD_DEBUG_OUTPUT": str(root/"host-trace/compile")},
                capture_output=True, text=True, timeout=15, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            shell, = (root/"host-trace").glob("compile.[0-9]*")
            linker, = (root/"host-trace").glob("compile.linker.*")
            self.assertEqual(shell.suffix, linker.suffix)
            self.assertIn("initialize program: /bin/sh", shell.read_text())
            trace = linker.read_text()
            self.assertIn("initialize program: " + str(root/"tools/ld.lld"), trace)
            self.assertIn("transferring control: " + str(root/"tools/ld.lld"), trace)
            self.assertNotIn(str(root/"host/../tools/ld.lld"), trace)
            self.assertIn("calling init: " + str(root/"host/lib/libc.so.6"), trace)
            self.assertIn("calling init: " + str(root/"host/loader"), trace)


if __name__ == "__main__":
    unittest.main()
