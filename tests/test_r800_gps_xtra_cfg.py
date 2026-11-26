"""Synthetic ARM/Thumb instruction graph tests."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "build"))
import r800_gps_xtra_cfg as target


def audit(body, isa="arm"):
    raw = ("00001000 <xtra_init>:\n" + body +
           "\n00002000 <other>:\n  2000: bx lr\n").encode()
    report = target.audit(raw, "xtra_init", isa)
    for field in ("disassembly_origin_verified", "instruction_widths_verified",
                  "control_flow_verified", "callback_layout_verified",
                  "runtime_verified", "safe_to_flash"):
        assert report[field] is False
    assert report["selected_abi"] is None
    return {n["address"]: n for n in report["nodes"]}


class CFGTests(unittest.TestCase):
    def test_arm_conditional_branch(self):
        nodes = audit("  1000: cmp r0, #0\n  1004: beq 0x1010 <xtra_init+0x10>\n"
                      "  1008: mov r4, r0\n  100c: b 0x1014\n"
                      "  1010: mov r4, r1\n  1014: bx lr")
        self.assertEqual(nodes[0x1004]["edges"], [
            {"kind": "branch", "target": 0x1010},
            {"kind": "fallthrough", "target": 0x1008}])
        self.assertEqual(nodes[0x100c]["edges"], [{"kind": "branch", "target": 0x1014}])
        self.assertTrue(all(n["reachable_in_partial_graph"] for n in nodes.values()))

    def test_thumb_cbz_and_width(self):
        nodes = audit("  1000: cbz r0, 0x1008\n  1002: ldr.w r3, [r0, #8]\n"
                      "  1006: blx r3\n  1008: bx lr", "thumb")
        self.assertEqual(nodes[0x1000]["edges"], [
            {"kind": "branch", "target": 0x1008},
            {"kind": "fallthrough", "target": 0x1002}])
        self.assertEqual(nodes[0x1006]["boundaries"], ["call_or_indirect_boundary"])

    def test_unconditional_branch_skips_unreachable(self):
        nodes = audit("  1000: b 0x1008\n  1004: mov r4, r0\n  1008: bx lr")
        self.assertFalse(nodes[0x1004]["reachable_in_partial_graph"])

    def test_loop_terminates(self):
        nodes = audit("  1000: cmp r0, #0\n  1004: bne 0x1000\n  1008: bx lr")
        self.assertEqual(len(nodes), 3)
        self.assertTrue(all(n["reachable_in_partial_graph"] for n in nodes.values()))

    def test_external_and_unresolved_targets(self):
        for operand, reason in (("0x2000", "branch_outside_function"),
                                ("r3", "branch_target_unresolved")):
            with self.subTest(operand=operand):
                nodes = audit("  1000: b " + operand + "\n  1004: bx lr")
                self.assertEqual(nodes[0x1000]["boundaries"], [reason])
                self.assertFalse(nodes[0x1004]["reachable_in_partial_graph"])

    def test_unknown_and_pc_write_stop(self):
        for insn in ("mov pc, r3", "pop {r4, pc}", "it eq", "tbb [r0, r1]",
                     "ldreq r3, [r0]", "bl 0x2000"):
            with self.subTest(insn=insn):
                nodes = audit("  1000: " + insn + "\n  1004: bx lr")
                self.assertEqual(nodes[0x1000]["edges"], [])
                self.assertFalse(nodes[0x1004]["reachable_in_partial_graph"])

    def test_gap_and_thumb_explicit_width(self):
        nodes = audit("  1000: mov r4, r0\n  1008: bx lr")
        self.assertEqual(nodes[0x1000]["boundaries"], ["fallthrough_unresolved"])
        nodes = audit("  1000: ldr.w r3, [r0]\n  1002: bx lr", "thumb")
        self.assertEqual(nodes[0x1000]["boundaries"], ["fallthrough_unresolved"])

    def test_bad_listing_rejected(self):
        for body in ("  1002: bx lr", "  1000: mov r4, r0\n  1000: bx lr",
                     "  1000: .word 0", "  1000: bx lr\n  1001: bx lr"):
            with self.subTest(body=body), self.assertRaises(ValueError):
                audit(body)

    def test_budget_rejected(self):
        body = "\n".join(f"  {0x1000 + 4*i:x}: mov r4, r0"
                         for i in range(target.MAX_NODES + 1))
        with self.assertRaises(ValueError):
            audit(body)


if __name__ == "__main__":
    unittest.main()
