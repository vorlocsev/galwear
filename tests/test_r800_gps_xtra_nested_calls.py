"""Synthetic nested-call and conditional return-summary tests."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "build"))
import r800_gps_xtra_nested_calls as target


def run(helper, depth=3, root="1000: bl 0x2000\n1004: ldr r3, [r0, #8]\n1008: blx r3"):
    raw = ("00001000 <init>:\n" + root + "\n00002000 <helper>:\n" + helper + "\n").encode()
    report = target.audit(raw, "init", "arm", depth)
    assert report["safe_to_flash"] is False and report["selected_abi"] is None
    return report["root"]


class NestedTests(unittest.TestCase):
    def test_identity_return(self):
        root = run("2000: bx lr")
        self.assertEqual(root["calls"][0]["callee"]["return_fact"], ("argument", 0, None))
        self.assertEqual([e["offset"] for e in root["events"]], [8, 8])

    def test_returned_field(self):
        root = run("2000: ldr r0, [r0, #4]\n2004: bx lr",
                   root="1000: bl 0x2000\n1004: blx r0")
        self.assertEqual(root["events"][0]["offset"], 4)
        self.assertEqual(root["events"][0]["load_address"], 0x2000)

    def test_nested_return(self):
        helper = ("2000: push {r4, lr}\n2004: bl 0x3000\n2008: pop {r4, lr}\n200c: bx lr\n"
                  "00003000 <inner>:\n3000: bx lr")
        root = run(helper)
        child = root["calls"][0]["callee"]
        self.assertEqual(child["calls"][0]["callee"]["function"], "inner")
        self.assertEqual([e["offset"] for e in root["events"]], [8, 8])
        limited = run(helper, depth=1)
        self.assertEqual(limited["calls"][0]["callee"]["calls"][0]["status"], "DEPTH_BOUNDARY")
        self.assertEqual(limited["events"], [])

    def test_conflicting_returns(self):
        root = run("2000: cmp r0, #0\n2004: beq 0x2010\n2008: mov r0, r1\n"
                   "200c: bx lr\n2010: bx lr")
        child = root["calls"][0]["callee"]
        self.assertTrue(child["return_paths_complete"])
        self.assertIsNone(child["return_fact"])
        self.assertEqual(root["events"], [])

    def test_incomplete_paths(self):
        for helper in ("2000: cmp r0, #0\n2004: beq 0x3000\n2008: bx lr",
                       "2000: cmp r0, #0\n2004: bne 0x2000\n2008: bx lr",
                       "2000: sub sp, #4\n2004: bx lr",
                       "2000: bl 0x3000\n2004: bx lr"):
            with self.subTest(helper=helper):
                root = run(helper)
                self.assertFalse(root["calls"][0]["callee"]["return_paths_complete"])
                self.assertEqual(root["events"], [])

    def test_recursion_boundary(self):
        root = run("2000: bl 0x1000\n2004: bx lr")
        child = root["calls"][0]["callee"]
        self.assertEqual(child["calls"][0]["status"], "RECURSION_BOUNDARY")
        self.assertIsNone(child["return_fact"])

    def test_unknown_return_address_not_claimed(self):
        report = target.audit(b"00001000 <init>:\n1000: bx lr\n", "init", "arm")
        self.assertTrue(report["return_address_not_verified"])
        self.assertFalse(report["control_flow_verified"])
        self.assertFalse(report["callback_layout_verified"])

    def test_invalid_depth(self):
        for depth in (-1, 5, True):
            with self.subTest(depth=depth), self.assertRaises(ValueError):
                run("2000: bx lr", depth=depth)


if __name__ == "__main__":
    unittest.main()
