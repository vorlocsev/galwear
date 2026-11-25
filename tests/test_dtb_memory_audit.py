"""Offline DTB memory audit regression tests; no donor image or watch."""
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "build"))
import r800_dtb_memory_audit as audit


class RangeTests(unittest.TestCase):
    def test_64bit_address(self):
        self.assertEqual(audit.ranges([1, 0, 4096], "x")[0]["start"], 1 << 32)

    def test_zero_size(self):
        with self.assertRaises(audit.AuditError):
            audit.ranges([0, 1, 0], "x")

    def test_malformed_cells(self):
        with self.assertRaises(audit.AuditError):
            audit.ranges([0, 1], "x")

    def test_overlap(self):
        with self.assertRaisesRegex(audit.AuditError, "Overlapping"):
            audit.validate_disjoint(audit.ranges([0, 0, 100, 0, 99, 1], "x"), "RAM")

    def test_adjacent_ranges(self):
        audit.validate_disjoint(audit.ranges([0, 0, 100, 0, 100, 1], "x"), "RAM")


@unittest.skipUnless(shutil.which("dtc") and shutil.which("fdtget"), "DTC tools required")
class DtbTests(unittest.TestCase):
    def compile(self, *, model="GALILEO-LARGE-BT", reserved="0x90000000", initrd=True):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        src = root / "fixture.dts"
        blob = root / "fixture.dtb"
        chosen = "linux,initrd-start = <0x84000000>; linux,initrd-end = <0x84200000>;" if initrd else ""
        src.write_text(f'''/dts-v1/;
/ {{
    compatible = "samsung,exynos9110";
    model = "{model}";
    #address-cells = <2>;
    #size-cells = <1>;
    memory@80000000 {{ device_type = "memory"; reg = <0 0x80000000 0x30000000>; }};
    reserved-memory {{
        #address-cells = <2>;
        #size-cells = <1>;
        ranges;
        fixed@90000000 {{ reg = <0 {reserved} 0x1000>; }};
        dynamic {{ size = <0x2000>; }};
    }};
    chosen {{ {chosen} }};
}};
''')
        subprocess.run(["dtc", "-I", "dts", "-O", "dtb", "-S", str(audit.DTB_SIZE),
                        "-o", str(blob), str(src)], check=True, capture_output=True)
        return blob

    def test_external_initrd_is_blocker(self):
        report = audit.inspect(self.compile())
        self.assertIn("EXTERNAL_INITRD_PRESENT_IN_EMBEDDED_MODE_UNVERIFIED", report["boot_blockers"])
        self.assertEqual(report["ram_banks"][0]["size_bytes"], 0x30000000)
        self.assertEqual(report["dynamic_reserved"][0]["size_bytes"], 0x2000)
        self.assertFalse(report["safe_to_flash"])

    def test_missing_external_initrd_is_not_boot_proof(self):
        report = audit.inspect(self.compile(initrd=False))
        self.assertIsNone(report["external_initrd"])
        self.assertFalse(report["boot_tested"])
        self.assertFalse(report["safe_to_flash"])

    def test_wrong_model_rejected(self):
        with self.assertRaisesRegex(audit.AuditError, "model"):
            audit.inspect(self.compile(model="other"))

    def test_outside_ram_reported(self):
        report = audit.inspect(self.compile(reserved="0x70000000"))
        self.assertTrue(any(x.startswith("FIXED_RESERVED_OUTSIDE_DECLARED_RAM")
                            for x in report["boot_blockers"]))

    def test_corrupted_header_rejected(self):
        blob = self.compile()
        raw = bytearray(blob.read_bytes())
        raw[0] = 0
        blob.write_bytes(raw)
        with self.assertRaisesRegex(audit.AuditError, "magic"):
            audit.inspect(blob)


if __name__ == "__main__":
    unittest.main()
