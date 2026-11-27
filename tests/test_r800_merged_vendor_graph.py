import sys
import unittest
import tempfile
import hashlib
from unittest.mock import patch
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "build"))
from r800_merged_vendor_graph import graph, external_audit, vndk_version, merged_symbol_audit, merged_namespace_audit
from r800_extract_ext4 import DonorSymbolInventory


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

    def test_merged_symbols_use_external_provider_and_versions(self):
        objects = {"bin/service": elf("a", None, ["liboutside.so"], "ET_EXEC")}
        report = {"objects": objects, "status": "MERGED_VENDOR_SYSTEM_CANDIDATES_ONLY",
                  "rejected_objects": [], **graph(objects)}
        system = {"status": "SYSTEM_PATH_CANDIDATES_ONLY",
                  "system_candidate_graph": {"liboutside.so": {
                      "status": "CANDIDATE_ONLY",
                      "candidates": [{"origin": "system", "path": "/lib/liboutside.so", "needed": []}]}},
                  "system_dependency_edges": []}
        def metadata(imports=(), exports=(), needs=(), definitions=()):
            return {"abi": "arm", "has_dynamic": True, "dynamic_symbol_count": 2,
                    "symbol_imports": list(imports), "symbol_exports": list(exports),
                    "unsupported_symbols": [], "version_needs": list(needs),
                    "version_definitions": list(definitions)}
        required = {"name": "fixture", "type": 2, "weak": False,
                    "version": "FIXTURE_1", "version_library": "liboutside.so"}
        provider = {"name": "fixture", "type": 2, "weak": False,
                    "version": "FIXTURE_1", "version_hidden": False}
        inventory = DonorSymbolInventory()
        inventory.add("vendor/bin/service", metadata(
            imports=[required], needs=[{"library": "liboutside.so", "version": "FIXTURE_1"}]))
        inventory.add("system:/lib/liboutside.so", metadata(
            exports=[provider], definitions=[{"version": "FIXTURE_1", "base": False}]))
        good = merged_symbol_audit(report, inventory, system)
        self.assertEqual(good["status"], "SYMBOL_CANDIDATES_ONLY")
        self.assertEqual(good["symbol_candidates"]["matched"], 1)
        self.assertFalse(good["symbol_resolution_verified"])
        inventory.objects["system:/lib/liboutside.so"]["symbol_exports"] = []
        bad = merged_symbol_audit(report, inventory, system)
        self.assertEqual(bad["status"], "REVIEW_REQUIRED")
        self.assertEqual(len(bad["symbol_candidates"]["missing_strong"]), 1)
        inventory.objects["system:/lib/liboutside.so"]["version_definitions"] = []
        self.assertTrue(merged_symbol_audit(report, inventory, system)["version_review"])
        inventory.exhausted = True
        self.assertTrue(merged_symbol_audit(report, inventory, system)["inventory_budget_exhausted"])

    def test_merged_namespace_links_and_unreached_hal(self):
        objects = {"bin/hw/service": elf("a", None, ["liboutside.so"], "ET_EXEC"),
                   "lib/hw/gps.r800.so": elf("b", "gps.r800.so")}
        report = {"objects": objects, "status": "MERGED_VENDOR_SYMBOL_CANDIDATES_ONLY",
                  "rejected_objects": [], **graph(objects)}
        system = {"status": "SYSTEM_PATH_CANDIDATES_ONLY",
                  "system_candidate_graph": {"liboutside.so": {
                      "status": "CANDIDATE_ONLY",
                      "candidates": [{"origin": "com.android.runtime",
                                      "path": "/lib/bionic/liboutside.so", "needed": []}]}},
                  "system_dependency_edges": []}
        raw = b"""dir.vendor = /vendor/bin
[vendor]
additional.namespaces = runtime
namespace.default.search.paths = /vendor/${LIB}
namespace.default.links = runtime
namespace.default.link.runtime.shared_libs = liboutside.so
namespace.runtime.search.paths = /apex/com.android.runtime/${LIB}/bionic
"""
        with tempfile.TemporaryDirectory() as tmp:
            config = Path(tmp)/"ld.config.txt"
            config.write_bytes(raw)
            good = merged_namespace_audit(report, config, hashlib.sha256(raw).hexdigest(), system)
            self.assertEqual(good["status"], "CONFIG_PATH_MATCHES_ONLY")
            self.assertEqual(good["checks"][0]["matching_namespaces"], ["runtime"])
            self.assertEqual(good["unreached_vendor_objects"], ["/vendor/lib/hw/gps.r800.so"])
            self.assertFalse(good["dlopen_coverage_verified"])
            bad = raw.replace(b"shared_libs = liboutside.so", b"shared_libs = libother.so")
            config.write_bytes(bad)
            self.assertEqual(merged_namespace_audit(report, config,
                hashlib.sha256(bad).hexdigest(), system)["status"], "REVIEW_REQUIRED")
            with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
                merged_namespace_audit(report, config, "0"*64, system)


if __name__ == "__main__":
    unittest.main()
