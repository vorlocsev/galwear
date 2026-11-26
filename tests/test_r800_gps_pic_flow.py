"""Synthetic ARM/Thumb PIC flow regressions."""
import struct
import unittest
from test_r800_gps_interface_xref import pic_image
from r800_gps_interface_xref import audit


def run(words, table=0x2100):
    raw = bytearray(pic_image(table))
    struct.pack_into('<' + 'I'*len(words), raw, 0x100, *words)
    return audit(bytes(raw), [('factory', 'arm', 0x1100, 4*len(words))])['code_ranges'][0]['pic_flow']


class FlowTests(unittest.TestCase):
    def test_nonadjacent_alias(self):
        # ADD at 0x1110, architectural PC 0x1118; 0xfe8 -> 0x2100.
        r = run([0xe3000fe8, 0xe320f000, 0xe3400000, 0xe1a01000, 0xe08f2001, 0xe12fff1e])
        self.assertEqual(r['events'][0]['table_va'], 0x2100)
        self.assertEqual(r['events'][0]['register'], 'r2')

    def test_join_same(self):
        r = run([0xe3000fe8, 0xe3400000, 0x0a000000, 0xe320f000, 0xe08f1000, 0xe12fff1e])
        self.assertEqual(len(r['events']), 1)

    def test_join_conflict(self):
        r = run([0xe3000fe8, 0xe3400000, 0x0a000000, 0xe3000000, 0xe08f1000, 0xe12fff1e])
        self.assertEqual(r['events'], [])

    def test_unreachable_skipped(self):
        r = run([0xe3000fe8, 0xe3400000, 0xea000000, 0xffffffff, 0xe08f1000, 0xe12fff1e])
        self.assertEqual(len(r['events']), 1)
        self.assertEqual(r['reached_instructions'], 5)

    def test_unresolved_path_suppresses_clues(self):
        for bad in (0xffffffff, 0xeb000000, 0x1a000040):
            with self.subTest(bad=bad):
                r = run([0xe3000fec, 0xe3400000, 0xe320f000, 0xe08f1000, bad])
                self.assertEqual(r['status'], 'PARTIAL_FLOW_REVIEW_REQUIRED')
                self.assertEqual(r['events'], [])

    def test_relocated_load_alias(self):
        # ADD at 0x1108, PC 0x1110, delta 0x70 -> relative slot 0x1180.
        r = run([0xe3000070, 0xe3400000, 0xe08f0000, 0xe1a02000, 0xe5921000, 0xe12fff1e])
        self.assertEqual(r['events'], [{'address': 0x1110, 'register': 'r1', 'slot_va': 0x1180,
                                       'table_va': 0x2100, 'kind': 'RELOCATED_TABLE_LOAD'}])

    def test_movt_without_movw(self):
        r = run([0xe3400000, 0xe08f1000, 0xe12fff1e])
        self.assertEqual(r['events'], [])


class ThumbFlowTests(unittest.TestCase):
    def run_flow(self, halfwords):
        raw = bytearray(pic_image(0x2100))
        struct.pack_into('<' + 'H'*len(halfwords), raw, 0x100, *halfwords)
        return audit(bytes(raw), [('factory', 'thumb', 0x1100, 2*len(halfwords))])['code_ranges'][0]['pic_flow']

    def test_nonadjacent_alias(self):
        # ADD at 0x110c, PC 0x1110, delta 0xff0.
        r = self.run_flow([0xf640, 0x70f0, 0xbf00, 0xf2c0, 0, 0x4601, 0x4479, 0x4770])
        self.assertEqual(r['events'], [{'address': 0x110c, 'register': 'r1', 'table_va': 0x2100, 'kind': 'COMPUTED_TABLE_ADDRESS'}])

    def test_branch_join(self):
        for fallthrough, expected in ((0xbf00, 1), (0x4610, 0)):
            r = self.run_flow([0xf640, 0x70f0, 0xf2c0, 0, 0xd000, fallthrough, 0x4478, 0x4770])
            self.assertEqual(len(r['events']), expected)

    def test_unreachable_skipped(self):
        r = self.run_flow([0xf640, 0x70f0, 0xf2c0, 0, 0xe000, 0xbe00, 0x4478, 0x4770])
        self.assertEqual(len(r['events']), 1)
        self.assertEqual(r['reached_instructions'], 5)

    def test_invalid_branch_and_it(self):
        for words in ([0xe000, 0xf240, 0, 0x4770], [0xbf08, 0x4770], [0xf000, 0xf800]):
            r = self.run_flow(words)
            self.assertEqual(r['status'], 'PARTIAL_FLOW_REVIEW_REQUIRED')
            self.assertEqual(r['events'], [])

    def test_load_alias(self):
        # PC at ADD is 0x110c; delta 0x74 -> 0x1180.
        r = self.run_flow([0xf240, 0x0074, 0xf2c0, 0, 0x4478, 0x4602, 0xf8d2, 0x1000, 0x4770])
        self.assertEqual(r['events'], [{'address': 0x110c, 'register': 'r1', 'slot_va': 0x1180, 'table_va': 0x2100, 'kind': 'RELOCATED_TABLE_LOAD'}])

    def test_unsupported_after_evidence(self):
        r = self.run_flow([0xf640, 0x70f4, 0xf2c0, 0, 0x4478, 0xbe00])
        self.assertEqual(r['events'], [])
        self.assertEqual(r['status'], 'PARTIAL_FLOW_REVIEW_REQUIRED')

    def test_missing_movw(self):
        r = self.run_flow([0xf2c0, 0, 0x4478, 0x4770])
        self.assertEqual(r['events'], [])


class LoopFlowTests(unittest.TestCase):
    def test_arm_loop_invariant(self):
        r = run([0xe3000ff0, 0xe3400000, 0xe08f1000, 0x1afffffd, 0xe12fff1e])
        self.assertTrue(r['converged'])
        self.assertEqual(r['back_edge_count'], 1)
        self.assertEqual(len(r['events']), 1)

    def test_arm_loop_conflict_removes_transient_event(self):
        r = run([0xe3000ff0, 0xe3400000, 0xe08f1000, 0xe3000000, 0x1afffffc, 0xe12fff1e])
        self.assertTrue(r['converged'])
        self.assertEqual(r['back_edge_count'], 1)
        self.assertEqual(r['events'], [])

    def test_thumb_loop_invariant(self):
        r = ThumbFlowTests().run_flow([0xf640, 0x70f4, 0xf2c0, 0, 0x4478, 0xd1fe, 0x4770])
        # The conditional branch targets itself; the preceding ADD is outside the loop.
        self.assertTrue(r['converged'])
        self.assertEqual(r['back_edge_count'], 1)
        self.assertEqual(len(r['events']), 1)

    def test_thumb_loop_conflict_removes_transient_event(self):
        r = ThumbFlowTests().run_flow([0xf640, 0x70f4, 0xf2c0, 0, 0x4478, 0xf240, 0, 0xd0fb, 0x4770])
        self.assertTrue(r['converged'])
        self.assertEqual(r['back_edge_count'], 1)
        self.assertEqual(r['events'], [])

    def test_self_loop_does_not_claim_termination(self):
        for r in (run([0xeafffffe]), ThumbFlowTests().run_flow([0xe7fe])):
            self.assertTrue(r['converged'])
            self.assertEqual(r['back_edge_count'], 1)
            self.assertFalse(r['range_end_reached'])
            self.assertFalse(r['control_flow_verified'])
            self.assertEqual(r['events'], [])

    def test_budget_suppresses_transient_evidence(self):
        from unittest.mock import patch
        with patch('r800_gps_pic_flow.MAX_STEPS', 3):
            r = run([0xe3000ff0, 0xe3400000, 0xe08f1000, 0xe12fff1e])
        self.assertFalse(r['converged'])
        self.assertEqual(r['events'], [])
        self.assertEqual(r['boundaries'][0]['reason'], 'iteration_budget_exceeded')

    def test_unknown_on_reachable_loop_path(self):
        r = run([0xe3000ff0, 0xe3400000, 0xe08f1000, 0x1afffffd, 0xffffffff])
        self.assertTrue(r['converged'])
        self.assertEqual(r['events'], [])
        self.assertEqual(r['status'], 'PARTIAL_FLOW_REVIEW_REQUIRED')

    def test_loop_edge_into_thumb_wide_tail_rejected(self):
        r = ThumbFlowTests().run_flow([0xf240, 0, 0xe7fd])
        self.assertEqual(r['status'], 'PARTIAL_FLOW_REVIEW_REQUIRED')
        self.assertEqual(r['events'], [])


class StackFlowTests(unittest.TestCase):
    def test_arm_push_pop_alias(self):
        r = run([0xe3000070, 0xe3400000, 0xe08f0000, 0xe92d0001, 0xe3000000,
                 0xe8bd0004, 0xe5921000, 0xe12fff1e])
        self.assertEqual(r['events'][0]['slot_va'], 0x1180)
        self.assertEqual(r['events'][0]['register'], 'r1')

    def test_arm_local_slot(self):
        r = run([0xe3000070, 0xe3400000, 0xe08f0000, 0xe24dd008, 0xe58d0004,
                 0xe3000000, 0xe59d2004, 0xe5921000, 0xe28dd008, 0xe12fff1e])
        self.assertEqual(r['events'][0]['table_va'], 0x2100)
        self.assertEqual(r['boundaries'], [])

    def test_thumb_push_pop_alias_and_return(self):
        r = ThumbFlowTests().run_flow([0xf240, 0x0074, 0xf2c0, 0, 0x4478,
                                       0xb501, 0xf240, 0, 0xbc04, 0x6811, 0xbd00])
        self.assertEqual(r['events'][0]['slot_va'], 0x1180)
        self.assertEqual(r['boundaries'], [])

    def test_thumb_stack_local_wide_load(self):
        r = ThumbFlowTests().run_flow([0xf240, 0x0074, 0xf2c0, 0, 0x4478,
                                       0xb082, 0x9001, 0xf240, 0, 0xf8dd, 0x2004,
                                       0x6811, 0xb002, 0x4770])
        self.assertEqual(r['events'][0]['table_va'], 0x2100)
        self.assertEqual(r['boundaries'], [])

    def test_stack_depth_conflict(self):
        r = run([0x0a000000, 0xe24dd004, 0xe320f000, 0xe12fff1e])
        self.assertEqual(r['events'], [])
        self.assertEqual(r['boundaries'][0]['reason'], 'ambiguous_stack_depth')

    def test_deallocated_slot_not_reused(self):
        r = run([0xe3000070, 0xe3400000, 0xe08f0000, 0xe24dd004, 0xe58d0000,
                 0xe28dd004, 0xe24dd004, 0xe59d2000, 0xe5921000, 0xe28dd004, 0xe12fff1e])
        self.assertEqual(r['events'], [])
        self.assertEqual(r['boundaries'], [])

    def test_invalid_stack_access_and_unbalanced_return(self):
        for words in ([0xe59d0000, 0xe12fff1e], [0xe24dd004, 0xe58d0002, 0xe12fff1e],
                      [0xe24dd004, 0xe12fff1e], [0xe24ddf80, 0xe12fff1e]):
            with self.subTest(words=words):
                r = run(words)
                self.assertEqual(r['status'], 'PARTIAL_FLOW_REVIEW_REQUIRED')
                self.assertEqual(r['events'], [])

    def test_unverified_pop_pc(self):
        for r in (run([0xe92d0001, 0xe8bd8000]), ThumbFlowTests().run_flow([0xb401, 0xbd00])):
            self.assertEqual(r['status'], 'PARTIAL_FLOW_REVIEW_REQUIRED')
            self.assertEqual(r['events'], [])


class CallFlowTests(unittest.TestCase):
    def arm(self, words, enabled=True):
        raw = bytearray(pic_image(0x2100))
        struct.pack_into('<' + 'I'*len(words), raw, 0x100, *words)
        return audit(bytes(raw), [('factory', 'arm', 0x1100, 4*len(words))],
                     assume_aapcs=enabled)['code_ranges'][0]['pic_flow']

    def thumb(self, words):
        raw = bytearray(pic_image(0x2100))
        struct.pack_into('<' + 'H'*len(words), raw, 0x100, *words)
        return audit(bytes(raw), [('factory', 'thumb', 0x1100, 2*len(words))],
                     assume_aapcs=True)['code_ranges'][0]['pic_flow']

    def test_opt_in_and_preserved_register(self):
        words = [0xe3004fe4, 0xe3404000, 0xe1a00004, 0xe1a0500e,
                 0xeb00002a, 0xe08f1004, 0xe1a0e005, 0xe12fff1e]
        self.assertEqual(self.arm(words, False)['events'], [])
        r = self.arm(words)
        self.assertEqual(r['boundaries'], [])
        self.assertEqual(r['events'][0]['table_va'], 0x2100)
        self.assertEqual(r['assumed_calls'][0]['arguments']['r0'], {'kind': 'constant', 'value': 0xfe4})
        self.assertEqual(r['assumed_calls'][0]['target_va'], 0x11c0)
        self.assertFalse(r['callee_execution_verified'])

    def test_caller_saved_and_platform_registers_lost(self):
        for reg in (0, 9, 12):
            words = [0xe3000fe4 | (reg << 12), 0xe3400000 | (reg << 12), 0xe320f000,
                     0xe1a0500e, 0xeb00002a, 0xe08f1000 | reg, 0xe1a0e005, 0xe12fff1e]
            r = self.arm(words)
            self.assertEqual(r['boundaries'], [])
            self.assertEqual(r['events'], [])

    def test_arm_blx_target_and_argument_address(self):
        r = self.arm([0xe3000ff0, 0xe3400000, 0xe08f0000, 0xe1a0500e,
                      0xfb00002a, 0xe1a0e005, 0xe12fff1e])
        call = r['assumed_calls'][0]
        self.assertEqual((call['target_va'], call['target_isa'], call['instruction']), (0x11c2, 'thumb', 'BLX'))
        self.assertEqual(call['arguments']['r0'], {'kind': 'address', 'value': 0x2100})

    def test_thumb_bl_and_blx(self):
        for tail, isa in ((0xf85d, 'thumb'), (0xe85e, 'arm')):
            r = self.thumb([0x4675, 0xf000, tail, 0x46ae, 0x4770])
            self.assertEqual(r['boundaries'], [])
            self.assertEqual(r['assumed_calls'][0]['target_va'], 0x11c0)
            self.assertEqual(r['assumed_calls'][0]['target_isa'], isa)

    def test_stack_and_lr_not_preserved(self):
        for words in ([0xe92d4010, 0xeb00002d, 0xe8bd8010],
                      [0xe92d4000, 0xeb00002d, 0xe8bd8000],
                      [0xeb00002e, 0xe12fff1e]):
            r = self.arm(words)
            self.assertEqual(r['status'], 'PARTIAL_FLOW_REVIEW_REQUIRED')
            self.assertEqual(r['assumed_calls'], [])

    def test_call_target_must_be_external_executable(self):
        for op in (0xebffffff, 0xeb000400, 0xe12fff30):
            r = self.arm([op, 0xe12fff1e])
            self.assertEqual(r['status'], 'PARTIAL_FLOW_REVIEW_REQUIRED')
            self.assertEqual(r['assumed_calls'], [])

    def test_memory_clobber_blocks_load(self):
        r = self.arm([0xe3004070, 0xe3404000, 0xe08f4004, 0xe1a0500e,
                      0xeb00002a, 0xe5941000, 0xe1a0e005, 0xe12fff1e])
        self.assertEqual(r['boundaries'], [])
        self.assertEqual(len(r['assumed_calls']), 1)
        self.assertEqual(r['events'], [])


class LeafFlowTests(unittest.TestCase):
    def evaluate(self, callee, *, isa='arm', caller=None, ranges=None, enabled=True):
        raw = bytearray(pic_image(0x2100))
        if caller is None:
            caller = [0xe3000070, 0xe3400000, 0xe08f0000, 0xe92d4010,
                      0xeb00002a if isa == 'arm' else 0xfa00002a,
                      0xe5901000, 0xe8bd8010]
        struct.pack_into('<' + 'I'*len(caller), raw, 0x100, *caller)
        fmt, width = ('I', 4) if isa == 'arm' else ('H', 2)
        struct.pack_into('<' + fmt*len(callee), raw, 0x1c0, *callee)
        if ranges is None:
            ranges = [(isa, 0x11c0, width*len(callee))]
        return audit(bytes(raw), [('factory', 'arm', 0x1100, 4*len(caller))],
                     assume_aapcs=enabled, callee_ranges=ranges)['code_ranges'][0]['pic_flow']

    def test_leaf_returns_argument_through_arm_and_thumb(self):
        for isa, body in (('arm', [0xe12fff1e]), ('thumb', [0x4770])):
            with self.subTest(isa=isa):
                r = self.evaluate(body, isa=isa)
                self.assertEqual(r['boundaries'], [])
                self.assertEqual(r['events'][0]['table_va'], 0x2100)
                self.assertEqual(r['assumed_calls'][0]['modeled_return_r0'], ('address', 0x1180))
                self.assertTrue(r['assumed_calls'][0]['callee_analyzed'])
                self.assertFalse(r['callee_execution_verified'])

    def test_leaf_conflicting_returns_drop_r0(self):
        r = self.evaluate([0x0a000000, 0xe3000000, 0xe12fff1e])
        self.assertEqual(r['boundaries'], [])
        self.assertIsNone(r['assumed_calls'][0]['modeled_return_r0'])
        self.assertEqual(r['events'], [])

    def test_leaf_multiple_equal_returns(self):
        r = self.evaluate([0x0a000000, 0xe12fff1e, 0xe12fff1e])
        self.assertEqual(r['assumed_calls'][0]['modeled_return_count'], 2)
        self.assertEqual(r['events'][0]['table_va'], 0x2100)

    def test_leaf_private_stack_and_saved_register(self):
        r = self.evaluate([0xe92d0010, 0xe1a04000, 0xe1a00004, 0xe8bd0010, 0xe12fff1e])
        self.assertEqual(r['events'][0]['table_va'], 0x2100)
        self.assertEqual(r['boundaries'], [])

    def test_leaf_unknown_loop_nested_or_fallthrough_rejected(self):
        for body in ([0xffffffff], [0xeafffffe], [0xeb000000, 0xe12fff1e], [0xe320f000], [0xe24dd004, 0xe12fff1e]):
            with self.subTest(body=body):
                r = self.evaluate(body)
                self.assertEqual(r['status'], 'PARTIAL_FLOW_REVIEW_REQUIRED')
                self.assertEqual(r['events'], [])

    def test_unlisted_leaf_does_not_propagate_return(self):
        r = self.evaluate([0xe12fff1e], ranges=[])
        self.assertEqual(r['events'], [])
        self.assertEqual(r['status'], 'PARTIAL_FLOW_REVIEW_REQUIRED')

    def test_leaf_ranges_validation(self):
        for ranges in ([('arm', 0x1100, 4)], [('arm', 0x2100, 4)], [('arm', 0x11c0, 4), ('thumb', 0x11c2, 2)]):
            with self.subTest(ranges=ranges), self.assertRaises(ValueError):
                self.evaluate([0xe12fff1e], ranges=ranges)
        with self.assertRaises(ValueError):
            self.evaluate([0xe12fff1e], enabled=False)


class NestedLeafTests(unittest.TestCase):
    def evaluate(self, second, *, depth=2, first=None, second_isa='arm', include_second=True):
        raw = bytearray(pic_image(0x2100))
        caller = [0xe3000070, 0xe3400000, 0xe08f0000, 0xe92d4010,
                  0xeb00002a, 0xe5901000, 0xe8bd8010]
        if first is None:
            first = [0xe92d4010, 0xeb000005 if second_isa == 'arm' else 0xfa000005, 0xe8bd8010]
        struct.pack_into('<7I', raw, 0x100, *caller)
        struct.pack_into('<' + 'I'*len(first), raw, 0x1c0, *first)
        fmt, width = ('I', 4) if second_isa == 'arm' else ('H', 2)
        struct.pack_into('<' + fmt*len(second), raw, 0x1e0, *second)
        ranges = [('arm', 0x11c0, 4*len(first))]
        if include_second:
            ranges.append((second_isa, 0x11e0, width*len(second)))
        return audit(bytes(raw), [('factory', 'arm', 0x1100, 4*len(caller))],
                     assume_aapcs=True, callee_ranges=ranges, callee_depth=depth)['code_ranges'][0]['pic_flow']

    def test_nested_arm_and_interworking(self):
        for isa, body in (('arm', [0xe12fff1e]), ('thumb', [0x4770])):
            with self.subTest(isa=isa):
                r = self.evaluate(body, second_isa=isa)
                self.assertEqual(r['boundaries'], [])
                self.assertEqual(r['events'][0]['table_va'], 0x2100)
                self.assertEqual(r['assumed_calls'][0]['modeled_return_r0'], ('address', 0x1180))
                self.assertEqual(r['assumed_calls'][0]['modeled_nested_depth'], 1)

    def test_depth_and_unlisted_nested_target(self):
        for kwargs in ({'depth': 1}, {'include_second': False}):
            r = self.evaluate([0xe12fff1e], **kwargs)
            self.assertEqual(r['status'], 'PARTIAL_FLOW_REVIEW_REQUIRED')
            self.assertEqual(r['events'], [])

    def test_mutual_recursion(self):
        r = self.evaluate([0xe92d4010, 0xebfffff5, 0xe8bd8010], depth=4)
        self.assertEqual(r['status'], 'PARTIAL_FLOW_REVIEW_REQUIRED')
        self.assertEqual(r['events'], [])

    def test_nested_conflicting_r0(self):
        r = self.evaluate([0x0a000000, 0xe3000000, 0xe12fff1e])
        self.assertEqual(r['boundaries'], [])
        self.assertIsNone(r['assumed_calls'][0]['modeled_return_r0'])
        self.assertEqual(r['events'], [])

    def test_nested_unsaved_lr(self):
        r = self.evaluate([0xe12fff1e], first=[0xe320f000, 0xeb000005, 0xe12fff1e])
        self.assertEqual(r['status'], 'PARTIAL_FLOW_REVIEW_REQUIRED')
        self.assertEqual(r['events'], [])

    def test_invalid_depth(self):
        for depth in (0, 5, True):
            with self.subTest(depth=depth), self.assertRaises(ValueError):
                self.evaluate([0xe12fff1e], depth=depth)

    def test_context_budget(self):
        from r800_gps_pic_flow import leaf_analyzer
        raw = struct.pack('<I', 0xe12fff1e)
        resolve = leaf_analyzer(raw, lambda va, size: (0, 5), {}, {}, {}, {(0x1000, 'arm'): 4})
        for i in range(32):
            self.assertTrue(resolve(0x1000, 'arm', {0: ('constant', i)})['accepted'])
        self.assertFalse(resolve(0x1000, 'arm', {0: ('constant', 32)})['accepted'])
        self.assertTrue(resolve(0x1000, 'arm', {0: ('constant', 0)})['accepted'])


class WideThumbTests(unittest.TestCase):
    def test_branch_encodings(self):
        from r800_gps_pic_flow import thumb_branch
        for a, b, va, result in ((0xf000, 0xb806, 0, (16, False)),
                                  (0xf000, 0x8004, 4, (16, True)),
                                  (0xf7ff, 0xbff6, 16, (0, False)),
                                  (0xf47f, 0xaff4, 20, (0, True)),
                                  (0xf000, 0xf806, 0, None),
                                  (0xf000, 0xe806, 0, None),
                                  (0xf380, 0x8000, 0, None)):
            with self.subTest(a=a, b=b):
                self.assertEqual(thumb_branch(a, b, 4, va), result)

    def test_wide_branch_skips_unreachable(self):
        r = ThumbFlowTests().run_flow([0xf000, 0xb801, 0xbe00, 0x4770])
        self.assertEqual(r['boundaries'], [])
        self.assertEqual(r['reached_instructions'], 2)

    def test_conditional_wide_branch_merges(self):
        for fallthrough, expected in ((0xbf00, 1), (0x4610, 0)):
            r = ThumbFlowTests().run_flow([0xf640, 0x70ee, 0xf2c0, 0,
                                          0xf000, 0x8001, fallthrough, 0x4478, 0x4770])
            self.assertEqual(r['boundaries'], [])
            self.assertEqual(len(r['events']), expected)

    def test_backward_wide_branch(self):
        r = ThumbFlowTests().run_flow([0xbf00, 0xf7ff, 0xbffd])
        self.assertTrue(r['converged'])
        self.assertEqual(r['back_edge_count'], 1)
        self.assertEqual(r['boundaries'], [])

    def test_wide_branch_tail_and_outside(self):
        for words in ([0xf000, 0xb801, 0xf240, 0, 0x4770], [0xf000, 0xb840, 0x4770]):
            r = ThumbFlowTests().run_flow(words)
            self.assertEqual(r['status'], 'PARTIAL_FLOW_REVIEW_REQUIRED')
            self.assertEqual(r['events'], [])

    def literal_report(self, words, data):
        raw = bytearray(pic_image(0x2100))
        struct.pack_into('<' + 'H'*len(words), raw, 0x100, *words)
        # Fixture's original relocated literal is at 0x1180. Add one at 0x1108.
        struct.pack_into('<I', raw, 0x20c, 32)
        struct.pack_into('<II', raw, 0x418, 0x1108, 23)
        return audit(bytes(raw), [('factory', 'thumb', 0x1100, 2*len(words))],
                     data_by_range={(0x1100, 'thumb'): data})['code_ranges'][0]

    def test_wide_literal_positive_and_negative(self):
        # Positive: PC=0x1104, slot=0x1108. Negative: PC=0x1110, same slot.
        for words, reg in (([0xf8df, 0x8004, 0xe002, 0xbf00, 0x2100, 0, 0x4770], 'r8'),
                           ([0xe004, 0xbf00, 0xbf00, 0xbf00, 0x2100, 0, 0xf85f, 0x9008, 0x4770], 'r9')):
            with self.subTest(reg=reg):
                r = self.literal_report(words, [(0x1108, 0x110c)])
                self.assertEqual(r['pic_flow']['boundaries'], [])
                self.assertEqual(r['pic_flow']['events'][0]['register'], reg)
                self.assertEqual(r['pic_flow']['events'][0]['slot_va'], 0x1108)
                self.assertEqual(r['literal_load_clues'][0]['register'], reg)

    def test_wide_literal_alignment_and_registers(self):
        from r800_gps_pic_flow import thumb_literal
        self.assertEqual(thumb_literal(0xf8df, 0x8004, 4, 0x1102), (8, 0x1108))
        for reg in (13, 14, 15):
            self.assertIsNone(thumb_literal(0xf8df, reg << 12, 4, 0x1100))
        r = self.literal_report([0xf8df, 0x8005, 0xe002, 0xbf00, 0x2100, 0, 0x4770], [(0x1108, 0x110c)])
        self.assertEqual(r['pic_flow']['events'], [])
        self.assertEqual(r['pic_flow']['boundaries'][0]['reason'], 'literal_outside_marked_data')

class ThumbITTests(unittest.TestCase):
    def evaluate(self, words, initial=None, relocations=None, data_ranges=()):
        from r800_gps_pic_flow import audit_thumb
        raw = struct.pack('<' + 'H'*len(words), *words)
        return audit_thumb(raw, 0, 0x1100, len(raw), relocations or {}, {}, {},
                           initial=initial, data_ranges=data_ranges)

    def test_single_it_unknown_condition_drops_conflict(self):
        r = self.evaluate([0xbf08, 0xf240, 1, 0x4770], {0: ('constant', 0)})
        self.assertEqual(r['boundaries'], [])
        self.assertIsNone(r['leaf_summary']['r0'])
        self.assertEqual(r['modeled_it_blocks'], 1)
        self.assertFalse(r['flags_verified'])

    def test_ite_correlated_paths_equal(self):
        for header in (0xbf0c, 0xbf14):  # ITE EQ / ITE NE
            r = self.evaluate([header, 0xf240, 7, 0xf240, 7, 0x4770])
            self.assertTrue(r['leaf_summary']['accepted'])
            self.assertEqual(r['leaf_summary']['r0'], ('constant', 7))

    def test_itt_preserves_restored_fact(self):
        r = self.evaluate([0xbf04, 0xf240, 1, 0xf240, 0, 0x4770], {0: ('constant', 0)})
        self.assertEqual(r['leaf_summary']['r0'], ('constant', 0))
        self.assertEqual(r['boundaries'], [])

    def test_three_and_four_instruction_blocks(self):
        for words in ([0xbf06, 0xf240, 1, 0xf240, 7, 0xf240, 7, 0x4770],
                      [0xbf01, 0xf240, 1, 0xf240, 2, 0xf240, 3, 0xf240, 7, 0x4770]):
            r = self.evaluate(words, {0: ('constant', 7)})
            self.assertEqual(r['leaf_summary']['r0'], ('constant', 7))

    def test_branch_into_body_rejected(self):
        r = self.evaluate([0xe000, 0xbf08, 0xbf00, 0x4770])
        self.assertEqual(r['status'], 'PARTIAL_FLOW_REVIEW_REQUIRED')
        self.assertEqual(r['events'], [])
        r = self.evaluate([0xe7ff, 0xbf08, 0xbf00, 0x4770])
        self.assertEqual(r['boundaries'], [])

    def test_unsupported_body_and_invalid_header(self):
        for words in ([0xbf08, 0x2001, 0x4770], [0xbf08, 0x4770], [0xbf04, 0xbf00],
                      [0xbf08, 0xbf08, 0xbf00, 0x4770], [0xbfe8, 0xbf00, 0x4770],
                      [0xbf08, 0xb401, 0x4770]):
            with self.subTest(words=words):
                r = self.evaluate(words)
                self.assertEqual(r['status'], 'PARTIAL_FLOW_REVIEW_REQUIRED')
                self.assertEqual(r['events'], [])

    def test_relocated_or_data_body_rejected(self):
        r = self.evaluate([0xbf08, 0xf240, 7, 0x4770], relocations={0x1104: (23, 0)})
        self.assertEqual(r['boundaries'][0]['reason'], 'relocated_it_body')
        r = self.evaluate([0xbf08, 0xbf00, 0x4770], data_ranges=[(0x1102, 0x1104)])
        self.assertEqual(r['boundaries'][0]['reason'], 'unsupported_it_body')

    def test_equal_it_result_reaches_pic_reference(self):
        # ADD at 0x110a, architectural PC 0x110e, delta 0xff2.
        r = ThumbFlowTests().run_flow([0xbf0c, 0xf640, 0x70f2, 0xf640, 0x70f2, 0x4478, 0x4770])
        self.assertEqual(r['boundaries'], [])
        self.assertEqual(r['events'][0]['table_va'], 0x2100)
        self.assertEqual(r['events'][0]['address'], 0x110a)
