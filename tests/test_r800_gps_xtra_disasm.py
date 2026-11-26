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



    def trace(self, body):
        return target.audit(fixture(body), "xtra_init")["conditional_register_trace"]

    def test_register_alias_and_indirect_call(self):
        trace = self.trace("  1000: mov r4, r0\n"
                           "  1002: ldr.w r3, [r4, #8]\n"
                           "  1006: mov r2, r3\n"
                           "  1008: blx r2")
        self.assertEqual(trace["events"], [
            {"kind": "argument_word_load", "address": 0x1002, "base": "r4",
             "destination": "r3", "offset": 8},
            {"kind": "loaded_word_indirect_call", "address": 0x1008,
             "register": "r2", "offset": 8, "load_address": 0x1002}])
        self.assertEqual(trace["stop_reason"], "call_boundary")

    def test_alias_overwritten(self):
        trace = self.trace("  1000: mov r4, r0\n"
                           "  1002: mov r4, r1\n"
                           "  1004: ldr r3, [r4, #8]\n"
                           "  1006: blx r3")
        self.assertEqual(trace["events"], [])

    def test_field_word_is_not_callback_base(self):
        trace = self.trace("  1000: ldr r0, [r0, #4]\n"
                           "  1004: ldr r3, [r0, #8]\n"
                           "  1008: blx r3")
        self.assertEqual(len(trace["events"]), 1)
        self.assertEqual(trace["events"][0]["offset"], 4)

    def test_stop_at_unknown_or_control_flow(self):
        for instruction in ("b 0x1008", "it eq", "adds r0, #4",
                            "bl 0x4000", "ldreq r3, [r0]"):
            with self.subTest(instruction=instruction):
                trace = self.trace("  1000: " + instruction +
                                   "\n  1004: ldr r3, [r0, #8]")
                self.assertEqual(trace["events"], [])
                self.assertEqual(trace["stop_reason"],
                                 "unsupported_instruction_or_control_flow")

    def test_discontinuity_and_unparsed_line(self):
        for body, reason in (
            ("  1004: ldr r3, [r0]", "address_discontinuity"),
            ("  1000: mov r4, r0\n  1008: ldr r3, [r4]", "address_discontinuity"),
            ("  1000: .word 0x1234\n  1004: ldr r3, [r0]", "unparsed_line"),
        ):
            with self.subTest(body=body):
                trace = self.trace(body)
                self.assertEqual(trace["events"], [])
                self.assertEqual(trace["stop_reason"], reason)

    def test_call_closes_prefix(self):
        trace = self.trace("  1000: ldr r3, [r0]\n"
                           "  1004: blx r3\n"
                           "  1008: ldr r2, [r0, #8]")
        self.assertEqual(len(trace["events"]), 2)
        self.assertEqual(trace["stop_reason"], "call_boundary")
        self.assertFalse(trace["full_control_flow_analyzed"])



    def test_push_pop_restores_argument(self):
        trace = self.trace("  1000: push {r0, r4, lr}\n"
                           "  1002: mov r0, r1\n"
                           "  1004: pop.w {r2, r4, lr}\n"
                           "  1008: ldr r3, [r2, #8]\n"
                           "  100c: blx r3")
        self.assertEqual([e["offset"] for e in trace["events"]], [8, 8])
        self.assertEqual(trace["stack_delta_at_stop"], 0)

    def test_prologue_and_stack_spill(self):
        trace = self.trace("  1000: push {r4-r7, lr}\n"
                           "  1002: sub sp, #12\n"
                           "  1004: str r0, [sp, #4]\n"
                           "  1006: mov r0, r1\n"
                           "  1008: ldr r4, [sp, #4]\n"
                           "  100a: ldr r3, [r4, #8]\n"
                           "  100c: blx r3")
        self.assertEqual([e["offset"] for e in trace["events"]], [8, 8])
        self.assertEqual(trace["stack_delta_at_stop"], -32)

    def test_unknown_store_clears_saved_argument(self):
        trace = self.trace("  1000: sub sp, #8\n"
                           "  1002: str r0, [sp]\n"
                           "  1004: str r1, [sp]\n"
                           "  1006: ldr r4, [sp]\n"
                           "  1008: ldr r3, [r4, #8]\n"
                           "  100a: blx r3")
        self.assertEqual(trace["events"], [])

    def test_reallocation_does_not_restore_stale_slot(self):
        trace = self.trace("  1000: sub sp, #4\n"
                           "  1002: str r0, [sp]\n"
                           "  1004: add sp, #4\n"
                           "  1006: sub sp, #4\n"
                           "  1008: ldr r4, [sp]\n"
                           "  100a: ldr r3, [r4, #8]")
        self.assertEqual(trace["events"], [])

    def test_stack_bounds(self):
        for instruction in ("pop {r4}", "add sp, #4", "sub sp, #4097",
                            "str r0, [sp]", "sub sp, #2"):
            with self.subTest(instruction=instruction):
                trace = self.trace("  1000: " + instruction)
                self.assertEqual(trace["stop_reason"], "stack_bounds")
                self.assertEqual(trace["events"], [])

    def test_unsupported_stack_forms(self):
        for instruction in ("pop {pc}", "push {r4, r4}", "push {r7-r4}"):
            with self.subTest(instruction=instruction):
                trace = self.trace("  1000: " + instruction)
                self.assertEqual(trace["stop_reason"], "unsupported_stack_register_list")
        trace = self.trace("  1000: str r0, [sp, #-4]!\n"
                           "  1004: ldr r3, [r0, #8]")
        self.assertEqual(trace["events"], [])



    def test_thumb_frame_pointer(self):
        trace = self.trace("  1000: push {r7, lr}\n"
                           "  1002: sub sp, #8\n"
                           "  1004: add r7, sp, #0\n"
                           "  1006: str r0, [r7, #4]\n"
                           "  1008: mov r0, r1\n"
                           "  100a: ldr r2, [r7, #4]\n"
                           "  100c: ldr r3, [r2, #8]\n"
                           "  100e: blx r3")
        self.assertEqual([e["offset"] for e in trace["events"]], [8, 8])

    def test_arm_frame_pointer_negative_offset(self):
        trace = self.trace("  1000: push {r11, lr}\n"
                           "  1004: add fp, sp, #4\n"
                           "  1008: sub sp, sp, #8\n"
                           "  100c: str r0, [fp, #-0x8]\n"
                           "  1010: mov r0, r1\n"
                           "  1014: ldr r2, [r11, #-8]\n"
                           "  1018: ldr r3, [r2, #4]\n"
                           "  101c: blx r3")
        self.assertEqual([e["offset"] for e in trace["events"]], [4, 4])

    def test_frame_overwritten_and_unknown_store(self):
        for middle in ("mov r7, r1", "str r1, [r7]"):
            with self.subTest(middle=middle):
                trace = self.trace("  1000: sub sp, #8\n"
                                   "  1002: mov r7, sp\n"
                                   "  1004: str r0, [r7]\n"
                                   "  1006: " + middle + "\n"
                                   "  1008: ldr r2, [r7]\n"
                                   "  100a: ldr r3, [r2, #8]")
                self.assertEqual(trace["events"], [])

    def test_released_frame_aliases_invalidated(self):
        trace = self.trace("  1000: sub sp, #8\n"
                           "  1002: mov r7, sp\n"
                           "  1004: mov r4, r7\n"
                           "  1006: add sp, #8\n"
                           "  1008: sub sp, #8\n"
                           "  100a: str r0, [sp]\n"
                           "  100c: ldr r2, [r4]\n"
                           "  100e: ldr r3, [r2, #8]")
        self.assertEqual(trace["events"], [])

    def test_frame_restore_sp(self):
        trace = self.trace("  1000: push {r0, lr}\n"
                           "  1002: mov r7, sp\n"
                           "  1004: sub sp, #8\n"
                           "  1006: mov r0, r1\n"
                           "  1008: mov sp, r7\n"
                           "  100a: pop {r2, lr}\n"
                           "  100e: ldr r3, [r2, #4]")
        self.assertEqual([e["offset"] for e in trace["events"]], [4])
        self.assertEqual(trace["stack_delta_at_stop"], 0)

    def test_frame_bounds_and_unknown_restore(self):
        for instruction in ("str r0, [r7, #-4]", "ldr r2, [r7, #8]",
                            "ldr r2, [r7, #2]", "add r11, sp, #12"):
            with self.subTest(instruction=instruction):
                trace = self.trace("  1000: sub sp, #8\n"
                                   "  1002: mov r7, sp\n"
                                   "  1004: " + instruction)
                self.assertEqual(trace["stop_reason"], "stack_bounds")
        self.assertEqual(self.trace("  1000: mov sp, r7")["stop_reason"],
                         "unsupported_move")


if __name__ == "__main__":
    unittest.main()
