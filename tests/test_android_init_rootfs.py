"""Synthetic single-namespace init rootfs planning and staging."""
import json
import hashlib
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "build"))
import r800_android_init_rootfs as a


class RootfsTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.product = self.root / "product"
        self.runtime = self.root / "runtime"
        self.report = {"status": "INIT_DEPENDENCY_CANDIDATES_ONLY",
                       "nodes": {}, "modules": {}, "linkers": {}, "edges": []}
        self.library = self.add("product", "system/lib64/libbase.so", b"base", ["libc.so"])
        self.libc = self.add("runtime", a.RUNTIME + "/lib64/bionic/libc.so", b"libc", [])
        self.linker = self.add("runtime", a.RUNTIME + "/bin/linker64", b"linker", [])
        self.report["linkers"][self.linker] = self.report["nodes"][self.linker]
        for module, name in a.MODULES.items():
            key = self.add("product", "system/bin/" + name, name.encode(), ["libbase.so"])
            self.report["modules"][module] = {
                **self.report["nodes"][key], "path": "system/bin/" + name,
                "interpreter": "/system/bin/linker64"}
            self.report["edges"].append({"from": key, "needed": "libbase.so",
                                          "candidates": [self.library]})
        self.report["edges"].append({"from": self.library, "needed": "libc.so",
                                      "candidates": [self.libc]})
        self.choices = {"libraries": {}, "interpreters": {"/system/bin/linker64": self.linker}}

    def add(self, origin, rel, data, needed):
        path = getattr(self, origin) / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        key = origin + ":" + rel
        self.report["nodes"][key] = {"sha256": hashlib.sha256(data).hexdigest(),
                                      "size_bytes": len(data), "needed": needed}
        return key

    def test_plan_and_stage(self):
        plan = a.plan(self.report, self.choices)
        self.assertEqual(plan["selected_libraries"]["libc.so"], self.libc)
        self.assertFalse(plan["namespace_resolution_tested"])
        self.assertFalse(plan["safe_to_flash"])
        out = self.root / "staged"
        a.stage(plan, self.product, self.runtime, out)
        self.assertEqual((out / "system/lib64/libbase.so").read_bytes(), b"base")
        self.assertEqual((out / "system/bin/init").stat().st_mode & 0o777, 0o644)
        self.assertFalse((out / "system/bin/linker64").exists())
        self.assertEqual((out / "linkerconfig/ld.config.txt").read_bytes(), a.CONFIG)
        self.assertEqual(plan["interpreter_aliases"]["system/bin/linker64"], "/" + a.RUNTIME + "/bin/linker64")

    def test_conflict_needs_explicit_choice(self):
        alternate = self.add("product", "system/lib64/bootstrap/libbase.so", b"other", [])
        for edge in self.report["edges"]:
            if edge["needed"] == "libbase.so":
                edge["candidates"].append(alternate)
        with self.assertRaisesRegex(ValueError, "Explicit library selection"):
            a.plan(self.report, self.choices)
        self.choices["libraries"]["libbase.so"] = alternate
        result = a.plan(self.report, self.choices)
        self.assertEqual(result["selected_libraries"]["libbase.so"], alternate)
        self.assertNotIn("system/lib64/libbase.so", result["files"])

    def test_missing_dependency(self):
        self.report["edges"][-1]["candidates"] = []
        with self.assertRaisesRegex(ValueError, "Missing dependency"):
            a.plan(self.report, self.choices)

    def test_missing_interpreter_mapping(self):
        self.choices["interpreters"] = {}
        with self.assertRaisesRegex(ValueError, "PT_INTERP"):
            a.plan(self.report, self.choices)

    def test_unused_library_choice(self):
        self.choices["libraries"]["unneeded.so"] = self.libc
        with self.assertRaisesRegex(ValueError, "Unused"):
            a.plan(self.report, self.choices)

    def test_source_mutation_before_stage(self):
        plan = a.plan(self.report, self.choices)
        (self.product / "system/lib64/libbase.so").write_bytes(b"fake")
        out = self.root / "staged"
        with self.assertRaisesRegex(ValueError, "Source changed"):
            a.stage(plan, self.product, self.runtime, out)
        self.assertFalse(out.exists())

    def test_duplicate_json_choice(self):
        with self.assertRaisesRegex(ValueError, "Duplicate selection key"):
            json.loads('{"libraries": {}, "libraries": {}}', object_pairs_hook=a.unique_object)

    def test_non_candidate_choice(self):
        self.choices["libraries"]["libbase.so"] = self.libc
        with self.assertRaisesRegex(ValueError, "not a candidate"):
            a.plan(self.report, self.choices)


if __name__ == "__main__":
    unittest.main()
