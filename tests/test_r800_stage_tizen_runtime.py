"""Assembly contract tests; no synthetic daemon is presented as real Tizen."""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "build"))
import r800_stage_tizen_runtime as runtime


class TizenRuntimeStageTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)

    def closure(self, omit=None, wrong=None, nonexec=None):
        pins = {name: hashlib.sha256(name.encode()).hexdigest() for name in runtime.DONORS}
        files = {name: {"mode": "0o755", "sha256": "a"*64} for name in runtime.TARGETS}
        files.update({"/lib/"+name: {"sha256": digest, "mode": "0o755"}
                      for name, digest in pins.items()})
        if omit:
            del files[omit]
        if wrong:
            files[wrong]["sha256"] = "0"*64
        if nonexec:
            files[nonexec]["mode"] = "0o644"
        raw = json.dumps({"files": files}).encode()
        (self.root/runtime.MANIFEST).write_bytes(raw)
        return hashlib.sha256(raw).hexdigest(), pins

    def test_closure_requires_all_targets_and_same_glibc(self):
        pin, pins = self.closure()
        with patch.object(runtime, "verify") as verify:
            result, raw = runtime.load_closure(self.root, pin, pins)
        verify.assert_called_once_with(self.root, expected=result)
        self.assertEqual(hashlib.sha256(raw).hexdigest(), pin)

    def test_missing_daemon_rejected(self):
        pin, pins = self.closure(omit="/usr/bin/gpsd")
        with patch.object(runtime, "verify"), self.assertRaisesRegex(ValueError, "target missing"):
            runtime.load_closure(self.root, pin, pins)

    def test_nonexecutable_daemon_rejected(self):
        pin, pins = self.closure(nonexec="/usr/bin/lhd")
        with patch.object(runtime, "verify"), self.assertRaisesRegex(ValueError, "not executable"):
            runtime.load_closure(self.root, pin, pins)

    def test_mixed_glibc_rejected(self):
        pin, pins = self.closure(wrong="/lib/libc.so.6")
        with patch.object(runtime, "verify"), self.assertRaisesRegex(ValueError, "glibc differ"):
            runtime.load_closure(self.root, pin, pins)

    def test_wrong_manifest_pin_rejected_before_verify(self):
        _, pins = self.closure()
        with patch.object(runtime, "verify") as verify, self.assertRaisesRegex(ValueError, "pin mismatch"):
            runtime.load_closure(self.root, "0"*64, pins)
        verify.assert_not_called()

    def test_identical_loader_merge(self):
        name = "r800dev/tzlite/lib/ld-linux.so.3"
        rows = {}
        total = runtime.merge_file(self.root, rows, name, b"loader", "0o644", "closure", 0)
        total = runtime.merge_file(self.root, rows, name, b"loader", "0o755", "linked", total)
        self.assertEqual(total, 6)
        self.assertEqual(rows[name]["mode"], "0o755")
        self.assertEqual((self.root/name).stat().st_mode & 0o777, 0o755)
        self.assertEqual(rows[name]["origins"], ["closure", "linked"])

    def test_conflicting_bytes_rejected(self):
        rows = {}
        name = "r800dev/tzlite/lib/libc.so.6"
        total = runtime.merge_file(self.root, rows, name, b"a", "0o755", "closure", 0)
        with self.assertRaisesRegex(ValueError, "Conflicting runtime file"):
            runtime.merge_file(self.root, rows, name, b"b", "0o644", "linked", total)
        self.assertEqual((self.root/name).read_bytes(), b"a")

    def test_non_glibc_mode_conflict_rejected(self):
        rows = {}
        name = "r800dev/fw/test.bin"
        total = runtime.merge_file(self.root, rows, name, b"a", "0o644", "first", 0)
        with self.assertRaisesRegex(ValueError, "Conflicting runtime mode"):
            runtime.merge_file(self.root, rows, name, b"a", "0o755", "second", total)


if __name__ == "__main__":
    unittest.main()
