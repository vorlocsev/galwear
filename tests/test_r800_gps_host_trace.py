"""Synthetic glibc runtime diagnostic review; no fixture executable is run."""
from pathlib import Path
import tempfile
import unittest
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/"build"))
from r800_gps_host_elf import audit, TOOLS
from r800_gps_host_trace import parse_log, summarize
from r800_gps_donor_snapshot import DONORS
from test_r800_gps_host_elf import fixture


class HostTraceTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        libs = self.root/"libs"
        libs.mkdir()
        self.loader = libs/"loader"
        self.loader.write_bytes(fixture())
        self.lib = libs/"liba.so"
        self.lib.write_bytes(fixture())
        tools = {}
        for name in TOOLS:
            tools[name] = self.root/name
            tools[name].write_bytes(fixture(["liba.so"], interpreter=True))
        self.report = audit(tools, directories=(libs,), loader=self.loader)
        self.stage = self.root/"stage"
        self.logs = self.stage/"host-trace"
        self.logs.mkdir(parents=True)
        self.captured = self.stage/"host/lib/liba.so"

    def log(self, tool="clang", pid=123, shell=False):
        program = "/bin/sh" if shell else str(self.stage/"tools"/tool)
        loader = self.loader if shell else self.stage/"host/loader"
        lib = self.lib if shell else self.captured
        lines = [
            "file=liba.so [0];  needed by " + program + " [0]",
            "find library=liba.so [0]; searching",
            "trying file=/unavailable/liba.so",
            "trying file=" + str(lib),
            "file=liba.so [0];  generating link map",
            "calling init: " + str(loader),
            "calling init: " + str(lib),
            "initialize program: " + program,
            "transferring control: " + program,
        ]
        if not shell:
            lines += ["calling fini:  [0]", "calling fini: " + str(lib) + " [0]"]
        return ("\n".join(f" {pid}:\t{line}" for line in lines)+"\n").encode()

    def test_failed_search_does_not_count_as_loaded(self):
        self.assertEqual(parse_log(self.log(), self.stage, self.report, tool="clang"),
                         ["lib/liba.so", "loader"])

    def test_external_loaded_library_rejected(self):
        raw = self.log().replace(str(self.captured).encode(), b"/external/liba.so")
        with self.assertRaisesRegex(ValueError, "escaped captured set"):
            parse_log(raw, self.stage, self.report, tool="clang")

    def test_late_dlopen_rejected(self):
        raw = self.log() + b" 123:\tfile=/external/plugin.so [0];  generating link map\n"
        with self.assertRaisesRegex(ValueError, "escaped captured set"):
            parse_log(raw, self.stage, self.report, tool="clang")

    def test_missing_and_mixed_diagnostics(self):
        for raw in (self.log().replace(b"calling fini:", b"ignored:"),
                    self.log()+b" 124:\tcalling init: /external/lib.so\n"):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                parse_log(raw, self.stage, self.report, tool="clang")

    def test_unobserved_required_dependency_rejected(self):
        raw = b"\n".join(line for line in self.log().splitlines()
                          if b"liba.so" not in line)
        with self.assertRaisesRegex(ValueError, "dependencies missing"):
            parse_log(raw, self.stage, self.report, tool="clang")

    def complete_logs(self):
        roles = {"donor-"+name: "llvm-readelf" for name in DONORS}
        roles.update({"compile":"clang", "compile.linker":"ld.lld", "result":"llvm-readelf"})
        for pid, (role, tool) in enumerate(roles.items(), 200):
            if role == "compile.linker":
                pid = 999
            (self.logs/f"{role}.{pid}").write_bytes(self.log(tool, pid))
        (self.logs/"compile.999").write_bytes(self.log("ld.lld", 999, shell=True))

    def test_complete_execution_set(self):
        self.complete_logs()
        evidence = summarize(self.stage, self.report)
        self.assertEqual(evidence["status"], "HOST_LOADER_DIAGNOSTICS_MATCH")
        self.assertEqual(len(evidence["observed"]), 7)
        self.assertFalse(evidence["host_isolated"])
        self.assertFalse(evidence["safe_to_flash"])
        next(self.logs.glob("compile.linker.*")).unlink()
        with self.assertRaisesRegex(ValueError, "Missing captured"):
            summarize(self.stage, self.report)

    def test_linker_wrapper_exec_pid_must_match(self):
        self.complete_logs()
        (self.logs/"compile.999").unlink()
        (self.logs/"compile.998").write_bytes(self.log("ld.lld", 998, shell=True))
        with self.assertRaisesRegex(ValueError, "wrapper and exec process IDs differ"):
            summarize(self.stage, self.report)

    def test_extra_and_pid_mismatched_logs(self):
        self.complete_logs()
        path = self.logs/"unexpected.123"
        path.write_bytes(self.log())
        with self.assertRaisesRegex(ValueError, "Unexpected host trace"):
            summarize(self.stage, self.report)
        path.unlink()
        (self.logs/"compile.123").write_bytes(self.log(pid=124))
        with self.assertRaisesRegex(ValueError, "filename/process mismatch"):
            summarize(self.stage, self.report)


if __name__ == "__main__":
    unittest.main()
