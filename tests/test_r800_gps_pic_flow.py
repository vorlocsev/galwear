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

class FlagFlowTests(unittest.TestCase):
    def test_compare_unsigned_and_signed_overflow(self):
        from r800_gps_pic_flow import compare_flags, condition_value
        s = {}
        compare_flags(s, 0x80000000, 1)
        self.assertEqual(s, {'N': False, 'Z': False, 'C': True, 'V': True})
        self.assertTrue(condition_value(s, 3) is False)  # CC
        self.assertTrue(condition_value(s, 11))  # LT
        compare_flags(s, 0x7fffffff, 0xffffffff)
        self.assertEqual(s, {'N': True, 'Z': False, 'C': False, 'V': True})
        self.assertTrue(condition_value(s, 12))  # GT

    def test_partial_flags_and_test_carry(self):
        from r800_gps_pic_flow import compare_flags, condition_value, arm_compare
        s = {'C': True, 'V': True, 0: ('constant', 0)}
        self.assertTrue(arm_compare(s, 0xe3100001))
        self.assertEqual({k: s[k] for k in 'NZCV'}, {'N': False, 'Z': True, 'C': True, 'V': True})
        self.assertTrue(arm_compare(s, 0xe3100102))  # TST r0, #0x80000000
        self.assertTrue(s['C'])
        compare_flags(s, None, 1, test=True)
        self.assertNotIn('Z', s)
        self.assertIsNone(condition_value(s, 0))
        self.assertFalse(condition_value({'Z': True}, 8))  # HI impossible

    def test_arm_known_branch_skips_bad_path(self):
        r = run([0xe3000000, 0xe3500000, 0x0a000000, 0xffffffff, 0xe12fff1e])
        self.assertEqual(r['boundaries'], [])
        self.assertEqual(r['reached_instructions'], 4)
        r = run([0xe3000000, 0xe3500000, 0x1a000040, 0xe12fff1e])
        self.assertEqual(r['boundaries'], [])

    def test_unknown_compare_clears_previous_flags(self):
        r = run([0xe3000000, 0xe3500000, 0xe3510000, 0x1a000040, 0xe12fff1e])
        self.assertEqual(r['boundaries'][0]['reason'], 'external_branch')

    def test_thumb_known_narrow_and_wide_branch(self):
        for words in ([0xf240, 0, 0x2800, 0xd000, 0xbe00, 0x4770],
                      [0xf240, 0, 0x2800, 0xf000, 0x8001, 0xbe00, 0x4770]):
            r = ThumbFlowTests().run_flow(words)
            self.assertEqual(r['boundaries'], [])
            self.assertEqual(r['reached_instructions'], 4)

    def test_known_it_condition_selects_lane(self):
        for cmp in (0x2800, 0x2801):
            r = ThumbITTests().evaluate([0xf240, 0, cmp, 0xbf0c, 0xf240, 7, 0xf240, 9, 0x4770])
            self.assertEqual(r['leaf_summary']['r0'], ('constant', 7 if cmp == 0x2800 else 9))

    def test_loop_weakens_flags_and_revisits_branch(self):
        # Initially Z=1; the taken loop body compares against 1 and returns to B.EQ.
        r = run([0xe3000000, 0xe3500000, 0x0a000000, 0xffffffff, 0xe3500001, 0xeafffffb])
        self.assertTrue(r['converged'])
        self.assertEqual(r['status'], 'PARTIAL_FLOW_REVIEW_REQUIRED')
        self.assertEqual(r['events'], [])

    def test_call_summary_drops_flags(self):
        from r800_gps_pic_flow import assumed_call
        state = {'sp': 0, 'Z': True, 'C': True, 4: ('constant', 7)}
        leaf = lambda *args: {'accepted': True, 'preserved_registers': [4], 'r0': None,
                              'return_count': 1, 'nested_depth': 0}
        self.assertIsNotNone(assumed_call(state, (0x2000, 'arm', 'BL'), 0x1100, 0x1100, 0x1200,
                                          lambda *args: (0, 5), leaf))
        self.assertEqual(state, {'sp': 0, 4: ('constant', 7)})

class AluFlowTests(unittest.TestCase):
    def test_arm_add_sub_overflow_and_carry(self):
        from r800_gps_pic_flow import arm_alu
        for word, lhs, rhs, result, flags in (
                (0xe0902001, 0x7fffffff, 1, 0x80000000, (True, False, False, True)),
                (0xe0902001, 0xffffffff, 1, 0, (False, True, True, False)),
                (0xe0502001, 0, 1, 0xffffffff, (True, False, False, False)),
                (0xe0502001, 0x80000000, 1, 0x7fffffff, (False, False, True, True))):
            s = {0: ('constant', lhs), 1: ('constant', rhs)}
            self.assertTrue(arm_alu(s, word))
            self.assertEqual(s[2], ('constant', result))
            self.assertEqual(tuple(s[k] for k in 'NZCV'), flags)

    def test_arm_logic_shifter_carry(self):
        from r800_gps_pic_flow import arm_alu
        s = {'C': False, 'V': True}
        self.assertTrue(arm_alu(s, 0xe3b00102))  # MOVS r0,#0x80000000
        self.assertEqual(s[0], ('constant', 0x80000000))
        self.assertTrue(s['C'])
        for word, result in ((0xe3900001, 0x80000001), (0xe2300001, 0x80000000), (0xe2100001, 0)):
            self.assertTrue(arm_alu(s, word))
            self.assertEqual(s[0], ('constant', result))
            self.assertTrue(s['C'])
            self.assertTrue(s['V'])
        self.assertTrue(s['Z'])

    def test_thumb_immediate_arithmetic(self):
        from r800_gps_pic_flow import thumb_alu
        s = {'C': True, 'V': True}
        for op, val in ((0x20ff, 255), (0x3001, 256), (0x3801, 255), (0x1c40, 256), (0x1e40, 255)):
            self.assertTrue(thumb_alu(s, op, 2))
            self.assertEqual(s[0], ('constant', val))
        self.assertTrue(s['C'])
        self.assertFalse(s['V'])

    def test_thumb_register_arithmetic_and_logic(self):
        from r800_gps_pic_flow import thumb_alu
        s = {0: ('constant', 3), 1: ('constant', 5), 'C': True, 'V': True}
        for op, result in ((0x4308, 7), (0x4048, 2), (0x4008, 0), (0x1840, 5), (0x1a40, 0), (0x0008, 5)):
            self.assertTrue(thumb_alu(s, op, 2))
            self.assertEqual(s[0], ('constant', result))
        self.assertTrue(s['C'])
        self.assertFalse(s['Z'])

    def test_unknown_values_clear_only_affected_facts(self):
        from r800_gps_pic_flow import arm_alu, thumb_alu
        s = {0: ('address', 0x2100), 2: ('constant', 9), 'N': False, 'Z': True, 'C': True, 'V': True}
        self.assertTrue(arm_alu(s, 0xe0102001))
        self.assertNotIn(2, s)
        self.assertNotIn('Z', s)
        self.assertTrue(s['C'] and s['V'])
        self.assertTrue(thumb_alu(s, 0x3001, 2))
        self.assertNotIn(0, s)
        self.assertFalse(any(k in s for k in 'NZCV'))

    def test_reject_unsupported_encodings(self):
        from r800_gps_pic_flow import arm_alu, thumb_alu
        for word in (0xe0902111, 0xe090f001, 0xe0802001, 0x00902001, 0xe3b10101, 0xe0102091):
            s = {0: ('constant', 1)}
            self.assertFalse(arm_alu(s, word))
            self.assertEqual(s, {0: ('constant', 1)})
        for word, width in ((0x4248, 2), (0x4348, 2), (0x2001, 4)):
            self.assertFalse(thumb_alu({}, word, width))

    def test_alu_flags_drive_branch_and_it(self):
        r = run([0xe3b00000, 0xe2500000, 0x0a000000, 0xffffffff, 0xe12fff1e])
        self.assertEqual(r['boundaries'], [])
        r = ThumbITTests().evaluate([0x2001, 0x3801, 0xbf0c, 0xf240, 7, 0xf240, 9, 0x4770])
        self.assertEqual(r['leaf_summary']['r0'], ('constant', 7))

    def test_alu_constant_reaches_pic_table(self):
        r = run([0xe3000fef, 0xe2900001, 0xe08f1000, 0xe12fff1e])
        self.assertEqual(r['events'][0]['table_va'], 0x2100)
        r = ThumbFlowTests().run_flow([0xf640, 0x70f7, 0x3801, 0x4478, 0x4770])
        self.assertEqual(r['events'][0]['table_va'], 0x2100)

class ShiftFlowTests(unittest.TestCase):
    def test_shift_boundaries(self):
        from r800_gps_pic_flow import shift_with_carry
        for kind, n, result in (("lsl", 0, (0x80000001, True)), ("lsl", 1, (2, True)),
                                ("lsl", 32, (0, True)), ("lsl", 33, (0, False)),
                                ("lsr", 32, (0, True)), ("lsr", 33, (0, False)),
                                ("asr", 32, (0xffffffff, True)), ("asr", 255, (0xffffffff, True)),
                                ("ror", 1, (0xc0000000, True)), ("ror", 32, (0x80000001, True)),
                                ("ror", 33, (0xc0000000, True))):
            with self.subTest(kind=kind, n=n):
                self.assertEqual(shift_with_carry(0x80000001, kind, n, True), result)

    def test_rrx_and_unknown_facts(self):
        from r800_gps_pic_flow import shift_with_carry
        self.assertEqual(shift_with_carry(3, 'rrx', 1, True), (0x80000001, True))
        self.assertEqual(shift_with_carry(3, 'rrx', 1, None), (None, True))
        self.assertEqual(shift_with_carry(None, 'lsl', 32, False), (0, None))
        self.assertEqual(shift_with_carry(3, 'ror', None, True), (None, None))

    def test_arm_shifted_operand_and_rrx(self):
        from r800_gps_pic_flow import arm_alu
        s = {0: ('constant', 0x80000001), 'C': True, 'V': True}
        for word, result, c in ((0xe1b01080, 2, True), (0xe1b01020, 0, True),
                                (0xe1b01040, 0xffffffff, True), (0xe1b01060, 0xc0000000, True)):
            self.assertTrue(arm_alu(s, word))
            self.assertEqual(s[1], ('constant', result))
            self.assertEqual(s['C'], c)
            self.assertTrue(s['V'])
        self.assertTrue(arm_alu(s, 0xe0902101))  # ADDS r2,r0,r1,LSL #2
        self.assertEqual(s[2], ('constant', 0x80000001))
        self.assertFalse(arm_alu(s, 0xe1b01210))  # register-controlled A32 shift not modeled

    def test_thumb_immediate_and_register_shifts(self):
        from r800_gps_pic_flow import thumb_alu
        for word, amount, result, c in ((0x0040, 0, 2, True), (0x0800, 0, 0, True),
                                        (0x1000, 0, 0xffffffff, True), (0x4088, 256, 0x80000001, False),
                                        (0x40c8, 33, 0, False), (0x4108, 255, 0xffffffff, True),
                                        (0x41c8, 32, 0x80000001, True)):
            s = {0: ('constant', 0x80000001), 1: ('constant', amount), 'C': False, 'V': True}
            self.assertTrue(thumb_alu(s, word, 2))
            self.assertEqual(s[0], ('constant', result))
            self.assertEqual(s['C'], c)
            self.assertTrue(s['V'])

    def test_adc_sbc_edge_cases(self):
        from r800_gps_pic_flow import alu_flags
        for op, a, b, cin, value, c, v in (('adc', 0xffffffff, 0, True, 0, True, False),
                ('adc', 0x7fffffff, 0, True, 0x80000000, False, True),
                ('sbc', 0, 0, False, 0xffffffff, False, False),
                ('sbc', 0x80000000, 0, False, 0x7fffffff, True, True),
                ('sbc', 0, 0xffffffff, False, 0, False, False)):
            s = {'C': cin}
            alu_flags(s, op, 0, a, b)
            self.assertEqual(s[0], ('constant', value))
            self.assertEqual((s['C'], s['V']), (c, v))

    def test_adc_sbc_decoders_and_input_carry(self):
        from r800_gps_pic_flow import arm_alu, thumb_alu
        s = {0: ('constant', 1), 1: ('constant', 2), 'C': True}
        self.assertTrue(arm_alu(s, 0xe0b02081))  # ADCS r2,r0,r1,LSL #1
        self.assertEqual(s[2], ('constant', 6))
        self.assertTrue(arm_alu(s, 0xe0d02001))
        self.assertEqual(s[2], ('constant', 0xfffffffe))
        s['C'] = True
        self.assertTrue(thumb_alu(s, 0x4148, 2))
        self.assertEqual(s[0], ('constant', 4))
        self.assertTrue(thumb_alu(s, 0x4188, 2))
        self.assertEqual(s[0], ('constant', 1))

    def test_unknown_shift_and_carry_clear_stale_facts(self):
        from r800_gps_pic_flow import arm_alu, thumb_alu
        s = {0: ('constant', 9), 'C': True, 'V': True, 'Z': False}
        self.assertTrue(thumb_alu(s, 0x4088, 2))
        self.assertEqual(s, {'V': True})
        s.update({0: ('constant', 1), 1: ('constant', 1), 2: ('constant', 7)})
        self.assertTrue(arm_alu(s, 0xe0b02001))
        self.assertEqual(s, {0: ('constant', 1), 1: ('constant', 1)})

    def test_shift_carry_selects_branch(self):
        r = run([0xe3b00102, 0xe1b00080, 0x2a000000, 0xffffffff, 0xe12fff1e])
        self.assertEqual(r['boundaries'], [])
        r = ThumbITTests().evaluate([0xf240, 1, 0x07c0, 0x0040, 0xbf2c, 0xf240, 7, 0xf240, 9, 0x4770])
        self.assertEqual(r['leaf_summary']['r0'], ('constant', 7))
