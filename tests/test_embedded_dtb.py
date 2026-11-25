"""Test exact DTS delta and compile a synthetic non-release DTB."""
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "build"))
import r800_embedded_dtb as a

SOURCE = '''/dts-v1/;
/ {
    compatible = "samsung,exynos9110";
    model = "GALILEO-LARGE-BT";
    #address-cells = <2>;
    #size-cells = <1>;
    memory@80000000 {
        device_type = "memory";
        reg = <0 0x80000000 0x30000000>;
    };
    reserved-memory {
        #address-cells = <2>;
        #size-cells = <1>;
        ranges;
        fixed@90000000 { reg = <0 0x90000000 0x1000>; };
    };
    chosen {
        bootargs = "console=ttySAC0 root=/dev/ram0";
        linux,initrd-start = <0x84000000>;
        linux,initrd-end = <0x841fffff>;
    };
};
'''


class DeltaTests(unittest.TestCase):
    def test_exact_two_lines_removed(self):
        expected = "".join(line for line in SOURCE.splitlines(keepends=True)
                           if "linux,initrd-" not in line)
        self.assertEqual(a.remove_external_initrd(SOURCE), expected)

    def test_changed_address_refused(self):
        with self.assertRaisesRegex(ValueError, "historical"):
            a.remove_external_initrd(SOURCE.replace("0x841fffff", "0x84200000"))

    def test_missing_end_refused(self):
        with self.assertRaises(ValueError):
            a.remove_external_initrd(SOURCE.replace("        linux,initrd-end = <0x841fffff>;\n", ""))

    def test_duplicate_property_refused(self):
        line = "        linux,initrd-start = <0x84000000>;\n"
        with self.assertRaises(ValueError):
            a.remove_external_initrd(SOURCE.replace(line, line + line))

    def test_outside_chosen_refused(self):
        with self.assertRaisesRegex(ValueError, "outside"):
            a.remove_external_initrd(SOURCE.replace('    model =', '    linux,initrd-start = <0x84000000>;\n    model ='))

    @unittest.skipUnless(shutil.which("dtc") and shutil.which("fdtget"), "DTC tools required")
    def test_compile_and_compare_full_tree(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            src = root / "source.dts"
            src.write_text(SOURCE)
            report = a.generate(src, root / "derived")
            self.assertTrue(report["all_other_canonical_properties_equal"])
            self.assertTrue(report["bootargs_unchanged"])
            self.assertFalse(report["safe_to_flash"])
            self.assertEqual(src.read_text(), SOURCE)
            with self.assertRaises(FileExistsError):
                a.generate(src, root / "derived")


if __name__ == "__main__":
    unittest.main()
