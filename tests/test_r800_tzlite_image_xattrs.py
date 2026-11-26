"""Strict reported-name parser, no xattr values in evidence."""
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"build"))
from r800_tzlite_image_xattrs import parse_list

BANNER="debugfs 1.47.0 (5-Feb-2023)\n"


class XattrTests(unittest.TestCase):
    def test_none_reported_not_absence(self):
        result=parse_list("",BANNER)
        self.assertEqual(result["status"],"NONE_REPORTED")
        self.assertFalse(result["absence_verified"])

    def test_categories(self):
        result=parse_list("Extended attributes:\n"
                          "  user.fixture (9) = \"sensitive\"\n"
                          "  security.capability (20) = 00 01 \n"
                          "  system.posix_acl_access (28)\n"
                          "  security.selinux (12) = \"private-label\"\n"
                          "  system.posix_acl_default (28)\n",BANNER)
        attrs=result["attributes"]
        self.assertEqual(attrs["security.capability"]["category"],"linux_capability")
        self.assertEqual(attrs["system.posix_acl_access"]["category"],"posix_acl")
        self.assertEqual(attrs["system.posix_acl_default"]["category"],"posix_acl")
        self.assertEqual(attrs["security.selinux"]["category"],"selinux_label")
        self.assertEqual(attrs["user.fixture"]["reported_bytes"],9)
        self.assertNotIn("sensitive",str(result))
        self.assertNotIn("private-label",str(result))

    def test_empty_attribute(self):
        self.assertEqual(parse_list("Extended attributes:\n  user.empty (0)\n",BANNER)
                         ["attributes"]["user.empty"]["reported_bytes"],0)

    def test_error_even_with_zero_status(self):
        with self.assertRaises(ValueError):
            parse_list("",BANNER+"ea_list: error while reading attributes\n")

    def test_duplicate_rejected(self):
        with self.assertRaises(ValueError):
            parse_list("Extended attributes:\n  user.x (1)\n  user.x (1)\n",BANNER)

    def test_invalid_size(self):
        with self.assertRaises(ValueError):
            parse_list("Extended attributes:\n  user.x (65537)\n",BANNER)

    def test_unsafe_name(self):
        with self.assertRaises(ValueError):
            parse_list("Extended attributes:\n  user.x;command (1)\n",BANNER)

    def test_missing_header(self):
        with self.assertRaises(ValueError):
            parse_list("  security.capability (20)\n",BANNER)

    def test_attribute_budget(self):
        with self.assertRaises(ValueError):
            parse_list("Extended attributes:\n"+"".join("  user.x%d (1)\n"%i for i in range(129)),BANNER)

    def test_empty_header_rejected(self):
        with self.assertRaises(ValueError):
            parse_list("Extended attributes:\n",BANNER)


if __name__=="__main__":
    unittest.main()
