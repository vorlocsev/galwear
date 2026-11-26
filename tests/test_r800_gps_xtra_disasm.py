"""Synthetic disassembly fixtures; no donor code execution."""
from pathlib import Path
import hashlib
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "build"))
import r800_gps_xtra_disasm as target


def fixture(body):
    return ("00001000 <xtra_init>:\n" + body +
            "\n00002000 <unrelated>:\n  2000: ldr r1, [r0, #8]\n").encode()


class DisassemblyTests(unittest.TestCase):
    def test_arm_and_thumb_loads(self):
        raw = fixture("  1000: ldr r1, [r0]\n"
                      "  1004: ldr.w r2, [r0, #0x4]\n"
                      "  1008: ldr.n r3, [r0, #8]\n"
                      "  100a: blx r3")
        report = target.audit(raw, "xtra_init")
        self.assertEqual(report["observed_offsets"], [0, 4, 8])
        self.assertEqual(report["indirect_calls"], [{"address": 0x100a, "register": "r3"}])
        self.assertEqual(report["disassembly_sha256"], hashlib.sha256(raw).hexdigest())

    def test_unrelated_functions_excluded(self):
        report = target.audit(fixture("  1000: ldr r1, [r0, #4]"), "xtra_init")
        self.assertEqual(report["observed_offsets"], [4])

    def test_nonmatching_accesses_excluded(self):
        raw = fixture("  1000: ldrb r1, [r0, #4]\n"
                      "  1004: ldr r1, [r2, #4]\n"
                      "  1008: ldr r1, [r0, #12]\n"
                      "  100c: ldr r1, [r0, #4]!\n"
                      "  1010: bl 0x1234")
        report = target.audit(raw, "xtra_init")
        self.assertEqual(report["observed_offsets"], [])
        self.assertEqual(report["indirect_calls"], [])

    def test_missing_and_duplicate_labels(self):
        for raw in (b"00001000 <other>:\n",
                    b"00001000 <xtra_init>:\n00002000 <xtra_init>:\n"):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                target.audit(raw, "xtra_init")

    def test_no_abi_selection_or_provenance_claim(self):
        report = target.audit(fixture("  1000: ldr r1, [r0, #8]"), "xtra_init")
        self.assertIsNone(report["selected_abi"])
        for name in ("disassembly_origin_verified", "register_provenance_verified",
                     "control_flow_verified", "callback_layout_verified",
                     "runtime_verified", "safe_to_flash"):
            self.assertFalse(report[name])

    def test_invalid_utf8_rejected(self):
        with self.assertRaises(ValueError):
            target.audit(b"\xff", "xtra_init")

    def test_evidence_budget(self):
        raw = fixture("  1000: ldr r1, [r0]\n" * 4097)
        with self.assertRaises(ValueError):
            target.audit(raw, "xtra_init")


if __name__ == "__main__":
    unittest.main()
