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
