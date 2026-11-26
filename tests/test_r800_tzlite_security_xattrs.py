"""Binary ACL and capability structural checks; never apply attributes."""
import struct
from pathlib import Path
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"build"))
from r800_tzlite_security_xattrs import parse_acl, parse_capability, UNDEFINED


def acl(entries,version=2):
    return struct.pack("<I",version)+b"".join(struct.pack("<HHI",*x) for x in entries)


BASE=[(1,7,UNDEFINED),(4,5,UNDEFINED),(32,5,UNDEFINED)]
NAMED=[(1,7,UNDEFINED),(2,4,123),(4,4,UNDEFINED),(8,5,456),
       (16,5,UNDEFINED),(32,5,UNDEFINED)]


class SecurityXattrsTests(unittest.TestCase):
    def test_base_acl(self):
        report=parse_acl(acl(BASE),0o755)
        self.assertTrue(report["mode_consistent"])
        self.assertFalse(report["mask_present"])
        self.assertFalse(report["effective_access_verified"])

    def test_extended_acl(self):
        report=parse_acl(acl(NAMED),0o755)
        self.assertTrue(report["mode_consistent"])
        self.assertTrue(report["mask_present"])
        self.assertEqual((report["named_user_count"],report["named_group_count"]),(1,1))

    def test_mode_mismatch(self):
        self.assertFalse(parse_acl(acl(NAMED),0o700)["mode_consistent"])

    def test_default_acl(self):
        self.assertIsNone(parse_acl(acl(NAMED),0o700,default=True,kind="directory")["mode_consistent"])
        with self.assertRaises(ValueError): parse_acl(acl(NAMED),0o755,default=True)

    def test_missing_mask(self):
        with self.assertRaises(ValueError): parse_acl(acl([x for x in NAMED if x[0]!=16]),0o755)

    def test_invalid_acl(self):
        for value in (acl(BASE,1),acl(BASE)[:-1],acl(BASE[::-1]),
                      acl([(1,8,UNDEFINED),*BASE[1:]]),
                      acl([(1,7,123),*BASE[1:]]),
                      acl([NAMED[0],NAMED[1],NAMED[1],*NAMED[2:]]),
                      acl([NAMED[0],(2,4,UNDEFINED),*NAMED[2:]])):
            with self.subTest(value=value.hex()),self.assertRaises(ValueError):
                parse_acl(value,0o755)

    def test_capability_v1(self):
        r=parse_capability(struct.pack("<III",0x01000001,1,0),"regular")
        self.assertEqual(r["permitted_count"],1)
        self.assertTrue(r["effective_flag"])

    def test_capability_v2(self):
        r=parse_capability(struct.pack("<IIIII",0x02000000,1,2,1,0),"regular")
        self.assertEqual((r["permitted_count"],r["inheritable_count"]),(2,1))
        self.assertFalse(r["effective_capabilities_verified"])

    def test_capability_v3(self):
        r=parse_capability(struct.pack("<IIIIII",0x03000001,1,0,0,0,1234),"regular")
        self.assertTrue(r["namespaced_root_id_present"])
        self.assertNotIn("root_id",r)

    def test_invalid_capability(self):
        for value in (b"",struct.pack("<III",0x04000000,1,0),
                      struct.pack("<III",0x01000002,1,0),
                      struct.pack("<III",0x02000001,1,0),
                      struct.pack("<IIIIII",0x03000001,1,0,0,0,UNDEFINED)):
            with self.assertRaises(ValueError): parse_capability(value,"regular")
        with self.assertRaises(ValueError):
            parse_capability(struct.pack("<III",0x01000001,1,0),"directory")


if __name__=="__main__":
    unittest.main()
