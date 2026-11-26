"""Test a compiled synthetic plugin without executing it."""
from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "build"))
from r800_gps_probe_plugin import check

RAW = Path(sys.argv.pop(1)).read_bytes()
PH = struct.unpack_from("<I", RAW, 28)[0]
NUM = struct.unpack_from("<H", RAW, 44)[0]
HEADERS = list(range(PH, PH+NUM*32, 32))

def ph(kind):
    return next(p for p in HEADERS if struct.unpack_from("<I", RAW, p)[0] == kind)

def tag(kind):
    off, _, _, size = struct.unpack_from("<4I", RAW, ph(2)+4)
    return next(p for p in range(off, off+size, 8) if struct.unpack_from("<I", RAW, p)[0] == kind)

def mapped(va):
    for p in HEADERS:
        kind, off, addr, _, size = struct.unpack_from("<5I", RAW, p)
        if kind == 1 and addr <= va < addr+size:
            return off+va-addr
    raise AssertionError("Fixture address not mapped")

def table(kind):
    return mapped(struct.unpack_from("<I", RAW, tag(kind)+4)[0])

class PluginTests(unittest.TestCase):
    def reject(self, offset, value, reason, fmt="I"):
        raw = bytearray(RAW)
        struct.pack_into("<"+fmt, raw, offset, value)
        with self.assertRaisesRegex(ValueError, reason):
            check(raw)

    def test_exact_plugin(self):
        report = check(RAW)
        self.assertEqual(report["exports"], ["probe_add"])
        self.assertEqual(report["imports"], 0)
        self.assertEqual(report["relocations"], 0)
        self.assertFalse(report["safe_to_flash"])

    def test_wrong_entry_and_type(self):
        self.reject(24, 4, "ET_DYN")
        self.reject(16, 2, "ET_DYN", "H")

    def test_interpreter_and_tls(self):
        for kind in (3,7):
            self.reject(ph(6), kind, "Unexpected plugin segment")

    def test_build_id_note_rejected(self):
        self.reject(ph(6), 4, "Unexpected plugin segment: 0x4")

    def test_stack_and_wx(self):
        self.reject(ph(0x6474e551)+24, 7, "stack")
        self.reject(ph(1)+24, 7, "plugin load")

    def test_dynamic_dependencies_and_init(self):
        for kind in (1,7,17,36,12,25,29):
            self.reject(tag(11), kind, "dynamic tag")

    def test_export_name_and_visibility(self):
        self.reject(table(5)+1, ord('x'), "export name", "B")
        self.reject(table(6)+16+13, 2, "function export", "B")
        self.reject(table(6)+16+14, 0, "function export", "H")

    def test_hash_reachability(self):
        off = table(4)
        buckets = struct.unpack_from("<I", RAW, off)[0]
        index = next(i for i in range(buckets) if struct.unpack_from("<I", RAW, off+8+4*i)[0] == 1)
        self.reject(off+8+4*index, 0, "export hash")

    def test_changed_instructions(self):
        va = struct.unpack_from("<I", RAW, table(6)+20)[0]
        self.reject(mapped(va), 0xe2800016, "instructions")

if __name__ == "__main__":
    unittest.main()
