"""Synthetic dynamic runtime metadata checks; no donor or device needed."""
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "build"))
import r800_android_dynamic_audit as a


PROBE = {"elf_type": 3, "interpreter": a.INTERP,
         "needed": ["libc.so", "libdl.so"], "soname": None}


class DynamicTests(unittest.TestCase):
    def test_probe_contract(self):
        a.validate_probe(PROBE)

    def test_wrong_interpreter(self):
        with self.assertRaisesRegex(ValueError, "Android PIE"):
            a.validate_probe({**PROBE, "interpreter": "/lib/ld-linux-aarch64.so.1"})

    def test_static_probe_rejected(self):
        with self.assertRaisesRegex(ValueError, "Android PIE"):
            a.validate_probe({**PROBE, "interpreter": None})

    def test_unexpected_dependency(self):
        with self.assertRaisesRegex(ValueError, "dependencies"):
            a.validate_probe({**PROBE, "needed": ["libc.so", "libdl.so", "libc.so.6"]})

    def test_no_runtime_is_compile_only(self):
        with patch.object(a, "inspect_elf", return_value=PROBE):
            result = a.inventory(Path("probe"), None, "readelf")
        self.assertEqual(result["status"], "DYNAMIC_PROBE_STATIC_ONLY")
        self.assertFalse(result["dynamic_android_linker_tested"])

    def test_runtime_dependency_closure(self):
        def inspect(path, readelf):
            if path.name == "probe":
                return PROBE
            if path.name == "linker64":
                return {"elf_type": 3, "interpreter": None, "needed": [], "soname": None}
            return {"elf_type": 3, "interpreter": None,
                    "needed": ["libm.so"] if path.name == "libc.so" else [],
                    "soname": path.name}
        with tempfile.TemporaryDirectory() as tmp:
            with patch.object(a, "inspect_elf", side_effect=inspect):
                result = a.inventory(Path("probe"), Path(tmp), "readelf")
        self.assertEqual(set(result["libraries"]), set(a.LIBS))
        self.assertFalse(result["runtime_authenticity_verified"])
        self.assertFalse(result["dynamic_android_linker_tested"])

    def test_symlinked_runtime_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "real").mkdir()
            (root / "alias").symlink_to(root / "real", target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "Symlinked"):
                a.runtime_file(root, "alias/libc.so")


if __name__ == "__main__":
    unittest.main()
