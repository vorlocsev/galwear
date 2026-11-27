import sys
import unittest
import tempfile
from unittest.mock import patch
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "build"))
from r800_merged_vendor_graph import graph, external_audit, vndk_version


def elf(sha, name, needed=(), kind="ET_DYN"):
    return {"sha256": sha, "soname": name, "needed": list(needed), "elf_type": kind}


class MergedVendorGraphTests(unittest.TestCase):
    def test_transitive_edges_and_external(self):
        objects = {
            "bin/hw/service": elf("a", None, ["liba.so"], "ET_EXEC"),
            "lib/liba.so": elf("b", "liba.so", ["libb.so"]),
            "lib/libb.so": elf("c", "libb.so", ["liba.so", "libc.so"]),
        }
        report = graph(objects)
        self.assertEqual(len(report["edges"]), 4)
        self.assertEqual(report["external_or_missing"], ["libc.so"])
        self.assertFalse(report["soname_conflicts"])
        self.assertFalse(report["rejected_providers"])

    def test_conflicting_and_rejected_providers(self):
        objects = {"bin/service": elf("a", None, ["liba.so"], "ET_EXEC"),
                   "lib/liba.so": elf("b", "wrong.so"),
                   "lib/hw/other.so": elf("c", "wrong.so")}
        report = graph(objects)
        self.assertEqual(report["soname_conflicts"][0]["soname"], "wrong.so")
        self.assertEqual(report["rejected_providers"][0]["needed"], "liba.so")

    def test_invalid_needed(self):
        with self.assertRaisesRegex(ValueError, "Invalid DT_NEEDED"):
            graph({"bin/service": elf("a", None, ["../lib.so"])})


    def test_actual_graph_external_probe_and_conflict(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root/"build.prop").write_text("ro.vndk.version=28\n")
            local = {"sha256": "a", "needed": ["libexternal.so"], "soname": "liblocal.so",
                     "elf_type": "ET_DYN"}
            report = {"objects": {"lib/liblocal.so": local},
                      "external_or_missing": ["libexternal.so"], "rejected_objects": [],
                      "rejected_providers": [], "soname_conflicts": []}
            external = {"status": "SYSTEM_PATH_CANDIDATES_ONLY",
                        "system_candidate_graph": {
                            "liblocal.so": {"candidates": [{"sha256": "b", "origin": "system",
                                                          "path": "/lib/liblocal.so"}]}}}
            with patch("r800_extract_ext4.system_dependency_candidates", return_value=external) as probe:
                result = external_audit(root, report, root/"system.img", "a"*64, True)
            self.assertEqual(result["status"], "REVIEW_REQUIRED")
            self.assertEqual(len(result["different_vendor_system_candidates"]), 1)
            self.assertEqual(probe.call_args.args[4]["external_names"], ["libexternal.so"])
            self.assertEqual(probe.call_args.args[5]["ro.vndk.version"], "28")
            self.assertTrue(probe.call_args.kwargs["include_apex"])
            (root/"default.prop").write_text("ro.vndk.version=29\n")
            with self.assertRaisesRegex(ValueError, "Conflicting"):
                vndk_version(root)


if __name__ == "__main__":
    unittest.main()
