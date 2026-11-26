"""Synthetic forward A32 PIC flow regressions."""
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
        for bad in (0xffffffff, 0xeb000000, 0x1a000040, 0xeafffffe):
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
        for words in ([0xe7fe], [0xe000, 0xf240, 0, 0x4770], [0xbf08, 0x4770], [0xf000, 0xf800]):
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
