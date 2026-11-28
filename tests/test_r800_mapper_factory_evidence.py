"""Check direct mapper factory symbol evidence without executing ELF code."""
from pathlib import Path
import sys
import unittest

BUILD = str(Path(__file__).resolve().parents[1] / "build")
if BUILD not in sys.path:
    sys.path.insert(0, BUILD)
from r800_graphics_inventory import LIB_PATTERN, entrypoint_evidence, mapper_factory_evidence


class MapperFactoryEvidenceTests(unittest.TestCase):
    path = "/vendor/lib/hw/android.hardware.graphics.mapper@2.1-impl.so"
    path20 = "/vendor/lib/hw/android.hardware.graphics.mapper@2.0-impl.so"

    @staticmethod
    def symbol(**kwargs):
        return dict({"name": "HIDL_FETCH_IMapper", "type": 2, "binding": 1,
                     "visibility": 0, "version_hidden": False}, **kwargs)

    def library(self, path, symbols, abi="arm", inspected=True):
        elf = {"dynamic_symbol_count": len(symbols) if inspected else None,
               "symbol_exports": symbols}
        return {"abi": abi, "entrypoints": entrypoint_evidence(path, elf)}

    def audit(self, libraries, abi="arm"):
        report = mapper_factory_evidence(libraries, abi)
        for key in ("factory_called", "interface_chain_verified", "mapper_2_1_verified",
                    "buffer_import_verified", "hardware_tested", "safe_to_flash"):
            self.assertIs(report[key], False, key)
        return report

    def test_direct_factory_export(self):
        r = self.audit({self.path: self.library(self.path, [self.symbol()])})
        self.assertEqual(r["status"], "STATIC_MAPPER_FACTORY_EXPORT_ONLY")
        self.assertEqual(r["direct_factory_candidates"], [self.path])

    def test_version_20_factory_does_not_prove_21(self):
        r = self.audit({self.path20: self.library(self.path20, [self.symbol()])})
        self.assertEqual(r["status"], "STATIC_MAPPER_FACTORY_EXPORT_ONLY")
        self.assertFalse(r["mapper_2_1_verified"])

    def test_missing_factory(self):
        r = self.audit({self.path: self.library(self.path, [])})
        self.assertEqual(r["status"], "REVIEW_REQUIRED")

    def test_hidden_local_object_or_untyped_factory(self):
        for fields in ({"version_hidden": True}, {"binding": 0},
                       {"visibility": 2}, {"type": 1}, {"type": 0}):
            with self.subTest(fields=fields):
                r = self.audit({self.path: self.library(self.path, [self.symbol(**fields)])})
                self.assertEqual(r["status"], "REVIEW_REQUIRED")

    def test_uninspected_dynamic_symbols(self):
        r = self.audit({self.path: self.library(self.path, [], inspected=False)})
        self.assertEqual(r["status"], "REVIEW_REQUIRED")

    def test_other_abi(self):
        r = self.audit({self.path: self.library(self.path, [self.symbol()], "arm64")})
        self.assertEqual(r["status"], "REVIEW_REQUIRED")
        self.assertEqual(r["other_abi_candidates"], [self.path])

    def test_unknown_abi(self):
        r = self.audit({self.path: self.library(self.path, [self.symbol()])}, None)
        self.assertEqual(r["status"], "REVIEW_REQUIRED")

    def test_ambiguous_factories(self):
        r = self.audit({p: self.library(p, [self.symbol()]) for p in (self.path, self.path20)})
        self.assertEqual(r["status"], "REVIEW_REQUIRED")

    def test_invalid_elf_candidate(self):
        r = self.audit({self.path: None})
        self.assertEqual(r["status"], "REVIEW_REQUIRED")
        self.assertEqual(r["invalid_candidates"], [self.path])

    def test_vendor_suffix_is_discovered(self):
        path = "/vendor/lib/hw/android.hardware.graphics.mapper@2.0-impl.vendor.so"
        # Android vendor variants with an impl- suffix are covered explicitly.
        path = path.replace("impl.vendor", "impl-vendor")
        self.assertIsNotNone(LIB_PATTERN.fullmatch(path.rsplit("/", 1)[-1]))
        r = self.audit({path: self.library(path, [self.symbol()])})
        self.assertEqual(r["direct_factory_candidates"], [path])


if __name__ == "__main__":
    unittest.main()
