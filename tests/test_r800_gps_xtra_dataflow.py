"""Synthetic multi-path register/stack dataflow tests."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "build"))
import r800_gps_xtra_dataflow as target


def audit(body):
    raw = ("00001000 <xtra_init>:\n" + body + "\n").encode()
    report = target.audit(raw, "xtra_init", "arm")
    assert report["selected_abi"] is None
    assert report["safe_to_flash"] is False
    assert report["control_flow_verified"] is False
    return report


class DataflowTests(unittest.TestCase):
    def diamond(self, right):
        return audit("1000: cmp r0, #0\n1004: beq 0x1010\n"
                     "1008: mov r4, r0\n100c: b 0x1014\n"
                     "1010: " + right + "\n1014: ldr r3, [r4, #8]\n1018: blx r3")

    def test_agreeing_registers(self):
        report = self.diamond("mov r4, r0")
        self.assertEqual([e["offset"] for e in report["events"]], [8, 8])

    def test_conflicting_registers(self):
        self.assertEqual(self.diamond("mov r4, r1")["events"], [])

    def test_agreeing_and_conflicting_stack(self):
        for reg, count in (("r0", 2), ("r1", 0)):
            with self.subTest(reg=reg):
                report = audit("1000: sub sp, #4\n1004: cmp r0, #0\n"
                               "1008: beq 0x1014\n100c: str r0, [sp]\n"
                               "1010: b 0x1018\n1014: str " + reg + ", [sp]\n"
                               "1018: ldr r4, [sp]\n101c: ldr r3, [r4, #8]\n"
                               "1020: blx r3")
                self.assertEqual(len(report["events"]), count)

    def test_different_stack_depths(self):
        report = audit("1000: cmp r0, #0\n1004: beq 0x1010\n"
                       "1008: sub sp, #4\n100c: b 0x1014\n"
                       "1010: mov r4, r0\n1014: ldr r3, [r0, #8]\n1018: blx r3")
        self.assertEqual(report["events"], [])
        self.assertIn(0x1014, report["unknown_state_nodes"])

    def test_loop_removes_transient_fact(self):
        report = audit("1000: mov r4, r0\n1004: cmp r0, #0\n"
                       "1008: beq 0x1014\n100c: mov r4, r1\n1010: b 0x1004\n"
                       "1014: ldr r3, [r4, #8]\n1018: blx r3")
        self.assertEqual(report["events"], [])
        self.assertGreater(report["iterations"], report["reached_nodes"])

    def test_unsupported_transfer_propagates_unknown(self):
        report = self.diamond("add r4, r0, #4")
        self.assertEqual(report["events"], [])
        self.assertIn(0x1014, report["unknown_state_nodes"])

    def test_unreachable_instruction_not_traced(self):
        report = audit("1000: b 0x1008\n1004: ldr r3, [r0, #8]\n1008: bx lr")
        self.assertEqual(report["events"], [])
        self.assertEqual(report["reached_nodes"], 2)

    def test_call_boundary(self):
        report = audit("1000: ldr r3, [r0, #4]\n1004: blx r3\n"
                       "1008: ldr r2, [r0, #8]")
        self.assertEqual([e["offset"] for e in report["events"]], [4, 4])
        self.assertEqual(report["reached_nodes"], 2)
        self.assertEqual(report["reachable_boundaries"][0]["address"], 0x1004)


if __name__ == "__main__":
    unittest.main()
