"""Synthetic AAPCS call assumptions, not donor execution."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "build"))
import r800_gps_xtra_calls as target
from r800_gps_xtra_dataflow import audit as strict_audit


def raw(body, helper=""):
    return ("00001000 <init>:\n" + body + "\n" + helper).encode()


class CallTests(unittest.TestCase):
    def analyze(self, body, helper="", isa="arm"):
        report = target.audit(raw(body, helper), "init", isa)
        self.assertIsNone(report["selected_abi"])
        self.assertFalse(report["safe_to_flash"])
        self.assertTrue(report["aapcs_assumed_not_verified"])
        return report

    def test_callee_argument_and_caller_saved_alias(self):
        report = self.analyze("1000: mov r4, r0\n1004: bl 0x2000 <helper>\n"
                              "1008: ldr r3, [r4, #8]\n100c: blx r3",
                              "00002000 <helper>:\n2000: ldr r3, [r0, #4]\n2004: blx r3\n")
        self.assertEqual([e["offset"] for e in report["caller"]["events"]], [8, 8])
        self.assertEqual([e["offset"] for e in report["direct_calls"][0]["events"]], [4, 4])

    def test_volatile_and_platform_registers_lost(self):
        for reg in ("r0", "r1", "r2", "r3", "r9", "r12"):
            with self.subTest(reg=reg):
                report = self.analyze(f"1000: mov {reg}, r0\n1004: bl 0x2000\n"
                                      f"1008: ldr r3, [{reg}, #8]\n100c: blx r3")
                self.assertEqual(report["caller"]["events"], [])

    def test_stack_facts_invalidated(self):
        report = self.analyze("1000: sub sp, #4\n1004: str r0, [sp]\n1008: bl 0x2000\n"
                              "100c: ldr r4, [sp]\n1010: ldr r3, [r4, #8]\n1014: blx r3")
        self.assertEqual(report["caller"]["events"], [])

    def test_argument_in_r1(self):
        report = self.analyze("1000: mov r1, r0\n1004: mov r0, r2\n1008: bl 0x2000\n100c: bx lr",
                              "00002000 <helper>:\n2000: ldr r3, [r1, #8]\n2004: blx r3\n")
        self.assertEqual(list(report["direct_calls"][0]["argument_facts"]), ["r1"])
        self.assertEqual([e["offset"] for e in report["direct_calls"][0]["events"]], [8, 8])

    def test_no_indirect_or_intra_function_resume(self):
        for insn in ("blx r3", "bl 0x1008"):
            with self.subTest(insn=insn):
                report = self.analyze("1000: mov r4, r0\n1004: " + insn +
                                      "\n1008: ldr r3, [r4, #8]")
                self.assertEqual(report["caller"]["events"], [])
                self.assertEqual(report["direct_calls"], [])

    def test_unknown_target_no_callee_analysis(self):
        report = self.analyze("1000: bl 0x2000\n1004: bx lr")
        self.assertEqual(report["direct_calls"][0]["callee_status"], "NOT_ANALYZED")

    def test_thumb_call_width_and_strict_default(self):
        body = "1000: mov r4, r0\n1002: bl 0x2000\n1006: ldr r3, [r4, #8]\n1008: blx r3"
        self.assertEqual(len(self.analyze(body, isa="thumb")["caller"]["events"]), 2)
        self.assertEqual(strict_audit(raw(body), "init", "thumb")["events"], [])
        bad = body.replace("1006:", "1004:").replace("1008:", "1006:")
        self.assertEqual(self.analyze(bad, isa="thumb")["caller"]["events"], [])

    def test_nested_call_not_followed(self):
        report = self.analyze("1000: bl 0x2000\n1004: bx lr",
                              "00002000 <helper>:\n2000: bl 0x3000\n2004: ldr r3, [r0, #8]\n"
                              "00003000 <nested>:\n3000: ldr r3, [r0, #4]\n3004: blx r3\n")
        self.assertEqual(report["direct_calls"][0]["events"], [])
        self.assertEqual(len(report["direct_calls"]), 1)


if __name__ == "__main__":
    unittest.main()
