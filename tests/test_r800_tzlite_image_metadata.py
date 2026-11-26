"""Strict parser for debugfs read-only inode metadata."""
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"build"))
from r800_tzlite_image_metadata import parse_inode

STAT="""Inode: 42   Type: regular    Mode:  04755   Flags: 0x80000
Generation: 0    Version: 0x00000000:00000000
User: 12345   Group: 23456   Project: 0   Size: 1024
File ACL: 0
Links: 1   Blockcount: 8
"""


class InodeMetadataTests(unittest.TestCase):
    def test_regular(self):
        self.assertEqual(parse_inode(STAT,42,"regular"),
                         {"inode":42,"kind":"regular","uid":12345,
                          "gid":23456,"mode":"0o4755","links":1})
    def test_directory(self):
        self.assertEqual(parse_inode(STAT.replace("regular","directory")
                                     .replace("04755","0750"),42,"directory")["mode"],"0o750")
    def test_debugfs_special_mode_padding(self):
        for rendered,expected in (("04755","0o4755"),("02755","0o2755"),
                                  ("01777","0o1777"),("07777","0o7777"),
                                  ("0000","0o0"),("0755","0o755"),
                                  ("4755","0o4755"),("755","0o755")):
            with self.subTest(rendered=rendered):
                self.assertEqual(parse_inode(STAT.replace("04755",rendered),42,"regular")["mode"],
                                 expected)

    def test_file_type_bits_rejected(self):
        for rendered in ("100755","104755","0100755","14755","004755"):
            with self.subTest(rendered=rendered),self.assertRaises(ValueError):
                parse_inode(STAT.replace("04755",rendered),42,"regular")

    def test_mode_cannot_cross_line(self):
        with self.assertRaises(ValueError):
            parse_inode(STAT.replace("Mode:  04755","Mode:\n04755"),42,"regular")

    def test_wrong_inode(self):
        with self.assertRaises(ValueError): parse_inode(STAT,43,"regular")
    def test_wrong_kind(self):
        with self.assertRaises(ValueError): parse_inode(STAT,42,"directory")
    def test_missing_owner(self):
        with self.assertRaises(ValueError): parse_inode(STAT.replace("User:","Unknown:"),42,"regular")
    def test_duplicate_owner(self):
        with self.assertRaises(ValueError): parse_inode(STAT+"User: 0 Group: 0\n",42,"regular")
    def test_invalid_mode(self):
        with self.assertRaises(ValueError): parse_inode(STAT.replace("4755","8755"),42,"regular")
    def test_invalid_uid(self):
        with self.assertRaises(ValueError): parse_inode(STAT.replace("12345","4294967296"),42,"regular")
    def test_zero_links(self):
        with self.assertRaises(ValueError): parse_inode(STAT.replace("Links: 1","Links: 0"),42,"regular")


if __name__=="__main__":
    unittest.main()
