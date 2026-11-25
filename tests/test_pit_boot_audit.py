"""Synthetic PIT geometry tests. No hardware or actual flash artifacts."""
from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "build"))
import r800_pit_boot_audit as a


def entry(name, filename, ident, offset, blocks, device_type=2):
    raw = bytearray(132)
    struct.pack_into("<III", raw, 0, 0, device_type, ident)
    struct.pack_into("<II", raw, 20, offset, blocks)
    raw[36:68] = name.encode().ljust(32, b"\0")
    raw[68:100] = filename.encode().ljust(32, b"\0")
    return bytes(raw)


def fixture(*, boot_blocks=36864, overlap=False, extra=None):
    rows = []
    for i, (filename, ident) in enumerate(a.EXPECTED_IMAGES.items()):
        start = 100000 * (i + 1)
        if overlap and filename == "dzImage-recovery":
            start -= 100000
        rows.append(entry("PART" + str(i), filename, ident, start,
                          boot_blocks if filename == "dzImage" else 1000))
    rows.append(entry("CSA", "", 99, 2000000, 1024))
    if extra is not None:
        rows.append(extra)
    return struct.pack("<II", 0x12349876, len(rows)).ljust(28, b"\0") + b"".join(rows)


class PitBootAuditTests(unittest.TestCase):
    def test_nominal_layout_never_authorizes_flash(self):
        report = a.inspect(fixture())
        self.assertEqual(report["status"], "STATIC_LAYOUT_ONLY")
        self.assertEqual(report["boot"]["assumed_capacity_bytes"], 18874368)
        self.assertFalse(report["safe_to_flash"])
        self.assertFalse(report["retail_sboot_verified"])

    def test_target_overlap(self):
        report = a.inspect(fixture(overlap=True))
        self.assertTrue(any(x.startswith("POSSIBLE_TARGET_RANGE_OVERLAP") for x in report["layout_issues"]))

    def test_unknown_neighbor_overlap(self):
        report = a.inspect(fixture(extra=entry("UNKNOWN", "", 101, 300001, 10)))
        self.assertEqual(report["status"], "STATIC_LAYOUT_CONFLICT")

    def test_neighbor_identifier_collision(self):
        report = a.inspect(fixture(extra=entry("UNKNOWN", "", 11, 2200000, 1)))
        self.assertTrue(any(x.startswith("TARGET_ID_COLLISION") for x in report["layout_issues"]))

    def test_unknown_neighbor_geometry(self):
        report = a.inspect(fixture(extra=entry("UNKNOWN", "", 101, 2200000, 0)))
        self.assertTrue(any(x.startswith("UNKNOWN_NEIGHBOR_GEOMETRY") for x in report["layout_issues"]))

    def test_separate_device_type_not_assumed_same_bank(self):
        report = a.inspect(fixture(extra=entry("OTHER", "", 101, 300001, 10, device_type=1)))
        self.assertEqual(report["status"], "STATIC_LAYOUT_ONLY")

    def test_candidate_overflow(self):
        report = a.inspect(fixture(), 18874369)
        self.assertIn("CANDIDATE_EXCEEDS_ASSUMED_BOOT_CAPACITY", report["layout_issues"])

    def test_candidate_exact_fit(self):
        self.assertEqual(a.inspect(fixture(), 18874368)["layout_issues"], [])

    def test_historical_capacity_difference(self):
        self.assertIn("BOOT_CAPACITY_DIFFERS_FROM_HISTORICAL_18_MIB",
                      a.inspect(fixture(boot_blocks=36000))["layout_issues"])

    def test_protected_overlap_rejected(self):
        with self.assertRaises(a.SafetyError):
            a.inspect(fixture(extra=entry("EFS", "", 102, 300001, 10)))

    def test_truncated_pit_rejected(self):
        with self.assertRaises(a.SafetyError):
            a.inspect(fixture()[:-1])


if __name__ == "__main__":
    unittest.main()
