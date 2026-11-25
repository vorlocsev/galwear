"""Synthetic archive checks; real AOSP output is not needed."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "build"))
import r800_android_rootfs_preflight as a

class PreflightTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.staged = self.root / "staged"
        self.product = self.root / "product"
        self.staged.mkdir()
        self.product.mkdir()
        self.init = self.root / "init"
        self.init.write_bytes(b"static-init")
        self.layout = {"status": "INIT_EXPERIMENTAL_ROOTFS_STAGED_ONLY",
                       "safe_to_flash": False, "files": {},
                       "selected_libraries": {"libc.so": "runtime:apex/com.android.runtime/lib64/bionic/libc.so"},
                       "interpreter_aliases": {"system/bin/linker64": "/" + a.LINKER},
                       "linkerconfig_sha256": a.sha(a.CONFIG)}
        self.metadata = {}
        for name in ("init", "galwear_property_service", "galwear_property_client"):
            self.add("system/bin/" + name, name.encode(), ["libc.so"], "/system/bin/linker64")
        self.add(a.LINKER, b"linker", [], None)
        self.add("apex/com.android.runtime/lib64/bionic/libc.so", b"libc", [], None)
        self.write(self.staged, "linkerconfig/ld.config.txt", a.CONFIG)
        self.write(self.product, a.CONTEXTS[0], b"debug.galwear. u:object_r:debug_prop:s0 prefix string\n")
        self.addCleanup(patch.stopall)
        patch.object(a, "validate_init", return_value={"sha256": a.sha(self.init.read_bytes())}).start()
        patch.object(a, "inspect_elf", side_effect=lambda path, _: self.metadata[str(path.relative_to(self.staged))]).start()

    def write(self, root, rel, blob):
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(blob)

    def add(self, rel, blob, needed, interp):
        self.write(self.staged, rel, blob)
        self.layout["files"][rel] = {"sha256": a.sha(blob), "size_bytes": len(blob)}
        self.metadata[rel] = {"sha256": a.sha(blob), "elf_type": 3,
                              "soname": Path(rel).name if rel.endswith(".so") else None,
                              "needed": needed, "interpreter": interp}

    def prepare(self):
        (self.staged / "guest-layout.json").write_text(json.dumps(self.layout))
        return a.prepare(self.staged, self.product, self.init)

    def test_deterministic_archive(self):
        blob, report = self.prepare()
        self.assertEqual(blob, self.prepare()[0])
        self.assertEqual(report["archive_sha256"], a.sha(blob))
        self.assertFalse(report["android_init_started"])
        self.assertFalse(report["selinux_policy_loaded"])
        self.assertEqual(report["guest_files"]["dev/console"]["mode"], 0o020600)
        self.assertEqual(report["guest_files"]["system/bin/linker64"]["mode"], 0o120777)

    def test_modified_file(self):
        self.write(self.staged, "system/bin/init", b"changed")
        with self.assertRaisesRegex(ValueError, "identity mismatch"):
            self.prepare()

    def test_missing_contexts(self):
        (self.product / a.CONTEXTS[0]).unlink()
        with self.assertRaisesRegex(ValueError, "contexts missing"):
            self.prepare()

    def test_invalid_alias(self):
        self.layout["interpreter_aliases"]["system/bin/linker64"] = "/etc/passwd"
        with self.assertRaisesRegex(ValueError, "Invalid guest linker"):
            self.prepare()

    def test_missing_library(self):
        del self.layout["files"]["apex/com.android.runtime/lib64/bionic/libc.so"]
        with self.assertRaisesRegex(ValueError, "Missing or ambiguous staged dependency"):
            self.prepare()

    def test_unexpected_path(self):
        self.layout["files"]["../../etc/passwd"] = {"sha256": "a"*64, "size_bytes": 1}
        with self.assertRaisesRegex(ValueError, "Unexpected staged path"):
            self.prepare()

    def test_archive_limit(self):
        with patch.object(a, "CAP", 16):
            with self.assertRaisesRegex(ValueError, "RAM budget"):
                self.prepare()

if __name__ == "__main__":
    unittest.main()
