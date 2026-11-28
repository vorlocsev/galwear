"""VINTF literal observation tests, no guest execution."""
import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"build"))
from r800_pixel_vintf_contract import parse

class PixelVintfContractTests(unittest.TestCase):
    def test_hidl_manifest(self):
        raw=b'<manifest version="1.0" type="device" target-level="5"><hal format="hidl"><name>android.hardware.gnss</name><transport>hwbinder</transport><version>2.1</version><fqname>@2.1::IGnss/default</fqname></hal></manifest>'
        r=parse(raw,"manifest")
        self.assertEqual(r["target_level"],"5")
        self.assertEqual(r["hals"][0]["versions"],["2.1"])
        self.assertEqual(r["hals"][0]["fqnames"],["@2.1::IGnss/default"])

    def test_matrix_ranges_and_optional(self):
        raw=b'<compatibility-matrix version="1.0" type="framework" level="5"><!-- comment --><hal format="hidl" optional="false"><name>android.hardware.graphics.composer</name><version>2.1-3</version><interface><name>IComposer</name><instance>default</instance></interface></hal></compatibility-matrix>'
        r=parse(raw,"compatibility-matrix")
        self.assertEqual(r["level"],"5")
        self.assertEqual(r["hals"][0]["versions"],["2.1-3"])
        self.assertEqual(r["hals"][0]["optional"],"false")
        self.assertEqual(r["hals"][0]["interfaces"][0]["instances"],["default"])

    def test_aidl_preserved(self):
        raw=b'<manifest version="2.0" type="device"><hal format="aidl"><name>android.hardware.light</name><fqname>ILights/default</fqname></hal></manifest>'
        r=parse(raw,"manifest")
        self.assertEqual(r["hals"][0]["format"],"aidl")
        self.assertEqual(r["hals"][0]["fqnames"],["ILights/default"])

    def test_reject_dtd_and_wrong_type(self):
        for raw in (b'<!DOCTYPE manifest [<!ENTITY x "x">]><manifest type="device"/>',
                    b'<manifest type="unknown"/>',b'<compatibility-matrix type="framework"/>'):
            with self.assertRaises(ValueError):
                parse(raw,"manifest")

if __name__=="__main__":
    unittest.main()
