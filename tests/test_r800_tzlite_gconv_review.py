"""Strict gconv text declaration subset."""
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"build"))
from r800_tzlite_gconv_review import parse


class GconvTextTests(unittest.TestCase):
    def test_basic(self):
        r=parse(b"alias UTF16// UTF-16//\nmodule UTF-16// INTERNAL UTF-16 1\n")
        self.assertEqual(r["alias_count"],1)
        self.assertEqual(r["module_paths"],["/usr/lib/gconv/UTF-16.so"])
    def test_extension(self):
        r=parse(b"module UTF-16// INTERNAL UTF-16.so\n")
        self.assertEqual(r["conversions"][0]["cost"],1)
    def test_path_escape(self):
        for name in (b"../evil",b"/tmp/evil",b".."):
            with self.assertRaises(ValueError):
                parse(b"module A// B// "+name+b"\n")
    def test_unknown(self):
        with self.assertRaises(ValueError):
            parse(b"include /tmp/config\nmodule A// B// TEST\n")
    def test_duplicate(self):
        with self.assertRaises(ValueError):
            parse(b"module A// B// X\nmodule a// b// Y\n")
    def test_cycle(self):
        with self.assertRaises(ValueError):
            parse(b"alias A// B//\nalias B// A//\nmodule A// INTERNAL X\n")
    def test_cost(self):
        with self.assertRaises(ValueError):
            parse(b"module A// B// X 0\n")
    def test_control(self):
        with self.assertRaises(ValueError):
            parse(b"module A// B// X\0\n")


if __name__=="__main__":
    unittest.main()
