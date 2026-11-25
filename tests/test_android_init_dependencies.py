"""Synthetic DT_NEEDED graph checks; no Android binaries needed."""
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "build"))
import r800_android_init_dependencies as a


class GraphTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.product = self.root / "product"
        self.runtime = self.root / "runtime"
        self.info = {}
        for name in a.MODULES.values():
            self.add(self.product, "system/bin/" + name, ["libbase.so"], interp="/system/bin/linker64")
        self.add(self.product, "system/lib64/libbase.so", ["libc.so"])
        self.add(self.runtime, a.RUNTIME_DIR + "/libc.so", ["libdl.so"])
        self.add(self.runtime, a.RUNTIME_DIR + "/libdl.so", ["libc.so"])
        self.add(self.runtime, a.RUNTIME + "/bin/linker64", [])
        # inventory() has its own inspect_elf import.
        self.addCleanup(patch.stopall)
        patch.object(a, "inspect_elf", side_effect=self.inspect).start()
        patch("r800_android_init_inventory.inspect_elf", side_effect=self.inspect).start()
        for name in a.MODULES.values():
            self.info[self.product / ("system/bin/" + name)]["needed"].append("libc.so")

    def add(self, root, rel, needed, interp=None, digest=None):
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"fixture")
        self.info[path] = {"elf_type": 3, "interpreter": interp,
                           "needed": list(needed), "soname": path.name if path.suffix == ".so" else None,
                           "size_bytes": 7, "sha256": digest or str(path)}

    def inspect(self, path, readelf):
        return dict(self.info[path])

    def test_transitive_cycle(self):
        report = a.graph(self.product, self.runtime)
        self.assertEqual(report["missing"], [])
        self.assertTrue(report["unambiguous_candidate_graph"])
        self.assertFalse(report["dependency_closure_verified"])
        self.assertFalse(report["namespace_resolution_tested"])
        self.assertIn("runtime:" + a.RUNTIME_DIR + "/libdl.so", report["nodes"])
        self.assertTrue(report["linkers"])

    def test_missing_transitive_dependency(self):
        (self.runtime / (a.RUNTIME_DIR + "/libdl.so")).unlink()
        report = a.graph(self.product, self.runtime)
        self.assertEqual(report["missing"], ["libdl.so"])
        self.assertFalse(report["all_dt_needed_have_candidates"])

    def test_different_bootstrap_candidate(self):
        self.add(self.product, "system/lib64/bootstrap/libbase.so", ["libc.so"])
        report = a.graph(self.product, self.runtime)
        self.assertIn("libbase.so", report["ambiguous"])
        self.assertFalse(report["unambiguous_candidate_graph"])

    def test_identical_copies_not_ambiguous(self):
        original = self.info[self.product / "system/lib64/libbase.so"]
        self.add(self.product, "system/lib64/bootstrap/libbase.so", ["libc.so"],
                 digest=original["sha256"])
        self.assertEqual(a.graph(self.product, self.runtime)["ambiguous"], {})

    def test_symlink_outside_tree_not_followed(self):
        path = self.runtime / (a.RUNTIME_DIR + "/libdl.so")
        path.unlink()
        path.symlink_to(self.product / "system/lib64/libbase.so")
        self.assertEqual(a.graph(self.product, self.runtime)["missing"], ["libdl.so"])

    def test_wrong_soname(self):
        self.info[self.runtime / (a.RUNTIME_DIR + "/libc.so")]["soname"] = "other.so"
        with self.assertRaisesRegex(ValueError, "library identity"):
            a.graph(self.product, self.runtime)

    def test_node_budget(self):
        with patch.object(a, "MAX_NODES", 3):
            with self.assertRaisesRegex(ValueError, "exceeds bounds"):
                a.graph(self.product, self.runtime)


if __name__ == "__main__":
    unittest.main()
