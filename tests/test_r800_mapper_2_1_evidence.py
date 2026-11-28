"""Literal IMapper candidates are not proof of runtime graphics compatibility."""
from pathlib import Path
import sys
import unittest

BUILD = str(Path(__file__).resolve().parents[1] / "build")
if BUILD not in sys.path:
    sys.path.insert(0, BUILD)
from r800_graphics_inventory import mapper_2_1_evidence
from r800_vintf_inventory import parse


class Mapper21EvidenceTests(unittest.TestCase):
    package = "android.hardware.graphics.mapper"
    interface = "/system/lib/" + package + "@2.1.so"
    implementation = "/vendor/lib/hw/" + package + "@2.1-impl.so"

    def setUp(self):
        self.entries = parse(b"""<manifest type="device"><hal format="hidl">
          <name>android.hardware.graphics.mapper</name>
          <transport arch="32">passthrough</transport>
          <version>2.1</version><interface><name>IMapper</name>
          <instance>default</instance></interface></hal></manifest>""",
          "/vendor/etc/vintf/manifest.xml")["entries"]
        self.libraries = {self.interface: {"abi": "arm"},
                          self.implementation: {"abi": "arm"}}

    def audit(self, abi="arm"):
        r = mapper_2_1_evidence(self.entries, self.libraries, abi)
        for key in ("vintf_merge_verified", "transport_arch_verified",
                    "namespace_resolution_verified", "mapper_factory_verified",
                    "mapper_2_1_verified", "native_handle_abi_verified",
                    "buffer_import_verified", "hardware_tested", "safe_to_flash"):
            self.assertIs(r[key], False, key)
        return r

    def test_matching_candidates_only(self):
        r = self.audit()
        self.assertEqual(r["status"], "STATIC_MAPPER_2_1_CANDIDATES_ONLY")
        self.assertEqual(r["blockers"], [])
        self.assertEqual(r["implementation_candidates"], [self.implementation])

    def test_missing_manifest(self):
        self.entries.clear()
        self.assertEqual(self.audit()["status"], "REVIEW_REQUIRED")

    def test_unsupported_transport(self):
        self.entries[0]["transport"] = "hwbinder"
        self.assertEqual(self.audit()["status"], "REVIEW_REQUIRED")

    def test_version_inheritance_not_inferred(self):
        self.entries[0]["version"] = [2, 0, 2]
        self.assertEqual(self.audit()["status"], "REVIEW_REQUIRED")

    def test_wrong_interface_instance(self):
        self.entries[0]["instance"] = "other"
        self.assertEqual(self.audit()["status"], "REVIEW_REQUIRED")

    def test_duplicate_manifest_entries_not_merged(self):
        self.entries.append(dict(self.entries[0]))
        self.assertEqual(self.audit()["status"], "REVIEW_REQUIRED")

    def test_missing_implementation(self):
        del self.libraries[self.implementation]
        self.assertEqual(self.audit()["status"], "REVIEW_REQUIRED")

    def test_wrong_client_abi(self):
        r = self.audit("arm64")
        self.assertEqual(r["status"], "REVIEW_REQUIRED")
        self.assertEqual(set(r["other_abi_candidates"]), set(self.libraries))

    def test_invalid_library_requires_review(self):
        self.libraries[self.implementation] = None
        r = self.audit()
        self.assertEqual(r["status"], "REVIEW_REQUIRED")
        self.assertEqual(r["invalid_candidates"], [self.implementation])

    def test_ambiguous_implementation(self):
        self.libraries["/odm/lib/hw/" + self.package + "@2.1-impl.so"] = {"abi": "arm"}
        self.assertEqual(self.audit()["status"], "REVIEW_REQUIRED")

    def test_legacy_gralloc_does_not_replace_mapper(self):
        del self.libraries[self.implementation]
        path = "/vendor/lib/hw/gralloc.r800.so"
        self.libraries[path] = {"abi": "arm"}
        r = self.audit()
        self.assertEqual(r["status"], "REVIEW_REQUIRED")
        self.assertEqual(r["legacy_gralloc_candidates"], [path])

    def test_unknown_client_abi(self):
        self.assertEqual(self.audit(None)["status"], "REVIEW_REQUIRED")


if __name__ == "__main__":
    unittest.main()
