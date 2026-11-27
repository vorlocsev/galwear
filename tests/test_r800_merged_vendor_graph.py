import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "build"))
from r800_merged_vendor_graph import graph


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


if __name__ == "__main__":
    unittest.main()
