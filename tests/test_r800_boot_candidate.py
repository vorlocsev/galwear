"""Synthetic NZIT candidate checks; no real firmware and no device access."""
from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "build"))
import r800_boot_candidate as boot


def dtb(model=b"GALILEO-LARGE-BT\0"):
    names = b"model\0compatible\0"
    def prop(offset, value):
        return struct.pack(">3I", 3, len(value), offset) + value + bytes((-len(value)) % 4)
    body = (struct.pack(">I", 1) + bytes(4) + prop(0, model) +
            prop(6, b"samsung,exynos9110\0") + struct.pack(">2I", 2, 9))
    raw = struct.pack(">10I", 0xd00dfeed, boot.DT_SIZE, 56, 56 + len(body),
                      40, 17, 16, 0, len(names), len(body))
    return (raw + bytes(16) + body + names).ljust(boot.DT_SIZE, bytes(1))


def template(tree=None):
    tree = dtb() if tree is None else tree
    table = struct.pack("<3I", 0x4e595845, 1, 6)
    for i in range(6):
        table += struct.pack("<5I", 1, 2, i, boot.DT_OFFSET, boot.DT_SIZE)
    table = table.ljust(boot.DT_OFFSET, bytes(1)) + tree
    header = struct.pack("<7I", 0x54495a4e, 0x8000, 64, 64 + 0x8000,
                         len(table), 0x1e00000, 2048)
    return header.ljust(2048, bytes(1)) + bytes(2048) + table + bytes([42]) * 272


def kernel(size=64):
    raw = bytearray(size)
    raw[56:60] = b"ARM\x64"
    return bytes(raw)


class BootCandidateTests(unittest.TestCase):
    def test_dtb_component_evidence_without_template(self):
        report = boot.component_evidence(dtb())
        self.assertEqual(report["status"], "DTB_STRUCTURE_ONLY")
        self.assertEqual(report["dtb_nodes"], 1)
        self.assertFalse(report["template_verified"])
        self.assertFalse(report["safe_to_flash"])

    def test_compiled_component_minimum_budget(self):
        report = boot.component_evidence(dtb(), kernel())
        self.assertEqual(report["minimum_container_bytes"],
                         boot.HEADER * 2 + boot.DT_OFFSET + boot.DT_SIZE + boot.SIG)
        self.assertFalse(report["partition_size_verified"])

    def test_compiled_component_overflow(self):
        with self.assertRaisesRegex(ValueError, "partition budget"):
            boot.component_evidence(dtb(), kernel(boot.PARTITION))

    def test_valid_roundtrip(self):
        ref = template()
        out = boot.build(kernel(), dtb(), ref)
        self.assertEqual(len(out), boot.PARTITION)
        self.assertEqual(boot.inspect_template(out), boot.inspect_template(ref))
        self.assertEqual(out[2048 + 56:2048 + 60], b"ARM\x64")

    def test_wrong_target(self):
        with self.assertRaisesRegex(ValueError, "model or SoC"):
            boot.build(kernel(), dtb(b"OTHER\0"), template())

    def test_wrong_kernel(self):
        with self.assertRaisesRegex(ValueError, "ARM64"):
            boot.build(bytes(64), dtb(), template())

    def test_wrong_table_offset(self):
        ref = bytearray(template())
        struct.pack_into("<I", ref, 4096 + 12 + 12, 4096)
        with self.assertRaisesRegex(ValueError, "EXYN entry"):
            boot.build(kernel(), dtb(), ref)

    def test_wrong_table_count(self):
        ref = bytearray(template())
        struct.pack_into("<I", ref, 4096 + 8, 5)
        with self.assertRaisesRegex(ValueError, "EXYN table"):
            boot.inspect_template(ref)

    def test_truncated_signature(self):
        with self.assertRaisesRegex(ValueError, "Truncated"):
            boot.inspect_template(template()[:-1])

    def test_partition_overflow(self):
        with self.assertRaisesRegex(ValueError, "partition size"):
            boot.build(kernel(boot.PARTITION), dtb(), template())


if __name__ == "__main__":
    unittest.main()
