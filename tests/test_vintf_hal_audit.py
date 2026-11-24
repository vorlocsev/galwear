"""Synthetic VINTF XML tests, no Android execution or real devices."""
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "build"))
import r800_vintf_hal_audit as audit


def xml(kind, side, body="", attributes=""):
    return f'<{kind} version="1.0" type="{side}" {attributes}>{body}</{kind}>'


def hal(name="android.hardware.graphics.composer", version="2.1", instance="default",
        fmt="hidl", optional=False, iface="IComposer"):
    return (f'<hal format="{fmt}" optional="{str(optional).lower()}"><name>{name}</name>'
            f'<version>{version}</version><interface><name>{iface}</name>'
            f'<instance>{instance}</instance></interface></hal>')


class VintfTests(unittest.TestCase):
    def setUp(self):
        t = tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        self.root = Path(t.name)
        self.put("vendor/etc/vintf/manifest.xml", xml("manifest", "device", hal(), 'target-level="5"'))
        self.put("system/etc/vintf/manifest.xml", xml("manifest", "framework"))
        self.put("vendor/etc/vintf/compatibility_matrix.xml", xml("compatibility-matrix", "device"))
        self.matrix = "system/etc/vintf/compatibility_matrix.5.xml"
        self.put(self.matrix, xml("compatibility-matrix", "framework", hal(), 'level="5"'))

    def put(self, name, data):
        p = self.root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(data, encoding="utf-8")

    def test_literal_match_is_not_compatibility(self):
        out = audit.audit(self.root)
        self.assertEqual(out["status"], "LITERAL_CANDIDATES_ONLY")
        self.assertFalse(out["libvintf_compatibility_verified"])
        self.assertFalse(out["safe_to_flash"])

    def test_missing_instance(self):
        self.put(self.matrix, xml("compatibility-matrix", "framework", hal(instance="external")))
        out = audit.audit(self.root)
        self.assertEqual(out["status"], "REVIEW_REQUIRED")
        self.assertEqual(len(out["missing_required_candidates"]), 1)

    def test_optional_missing(self):
        self.put(self.matrix, xml("compatibility-matrix", "framework", hal(instance="external", optional=True)))
        out = audit.audit(self.root)
        self.assertFalse(out["missing_required_candidates"])
        self.assertEqual(out["status"], "LITERAL_CANDIDATES_ONLY")

    def test_hidl_range_and_fqname_fragment(self):
        self.put("vendor/etc/vintf/manifest.xml", xml("manifest", "device"))
        self.put("vendor/etc/vintf/manifest/composer.xml", xml("manifest", "device",
                 '<hal format="hidl"><name>android.hardware.graphics.composer</name>'
                 '<fqname>@2.2::IComposer/default</fqname></hal>'))
        self.put(self.matrix, xml("compatibility-matrix", "framework", hal(version="2.1-3")))
        self.assertEqual(audit.audit(self.root)["status"], "LITERAL_CANDIDATES_ONLY")

    def test_aidl_range(self):
        self.put("vendor/etc/vintf/manifest.xml", xml("manifest", "device",
                 hal(name="android.hardware.test", fmt="aidl", version="2", iface="ITest")))
        self.put(self.matrix, xml("compatibility-matrix", "framework",
                 hal(name="android.hardware.test", fmt="aidl", version="1-3", iface="ITest")))
        self.assertEqual(audit.audit(self.root)["status"], "LITERAL_CANDIDATES_ONLY")

    def test_matrix_levels_not_merged_or_selected(self):
        self.put("system/etc/vintf/compatibility_matrix.6.xml",
                 xml("compatibility-matrix", "framework", hal(version="3.0"), 'level="6"'))
        out = audit.audit(self.root)
        self.assertEqual(out["status"], "REVIEW_REQUIRED")
        self.assertFalse(out["fcm_level_selection_verified"])
        self.assertEqual(len(out["comparisons"]), 2)

    def test_override_regex_not_silently_accepted(self):
        body = hal().replace('<hal ', '<hal override="true" ').replace(
            '<instance>default</instance>', '<regex-instance>.*</regex-instance>')
        self.put(self.matrix, xml("compatibility-matrix", "framework", body))
        out = audit.audit(self.root)
        self.assertEqual(out["status"], "REVIEW_REQUIRED")
        self.assertEqual(len(out["unsupported"]), 2)

    def test_reject_dtd_and_invalid_ranges(self):
        with self.assertRaises(ValueError):
            audit.parse_document(b'<!DOCTYPE manifest [<!ENTITY x "test">]><manifest type="device"/>', "fake")
        with self.assertRaises(ValueError):
            audit.version_range("2.3-1", "hidl")

    def test_missing_documents_not_pass(self):
        (self.root / "vendor/etc/vintf/compatibility_matrix.xml").unlink()
        self.assertEqual(audit.audit(self.root)["status"], "REVIEW_REQUIRED")

    def test_invalid_xml_not_pass(self):
        self.put(self.matrix, "<broken>")
        out = audit.audit(self.root)
        self.assertEqual(out["status"], "REVIEW_REQUIRED")
        self.assertTrue(out["errors"])


if __name__ == "__main__":
    unittest.main()
