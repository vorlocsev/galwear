"""Synthetic hiddenapi layout only; no executable DEX or policy edits."""
import hashlib
from pathlib import Path
import struct
import sys
import unittest
import zlib

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"build"))
from r800_dex_hiddenapi_observation import observe
from r800_art_inventory import dex_inventory


def fixture():
    # Header + one synthetic class-def + terminal map.
    old=bytearray(144+4+36)
    old[:8]=b"dex\n039\0"
    struct.pack_into("<III",old,32,len(old),112,0x12345678)
    struct.pack_into("<I",old,52,144)
    struct.pack_into("<II",old,96,1,112)
    struct.pack_into("<II",old,104,len(old)-144,144)
    struct.pack_into("<I",old,144,3)
    for i,entry in enumerate(((0,0,1,0),(6,0,1,112),(0x1000,0,1,144))):
        struct.pack_into("<HHII",old,148+i*12,*entry)
    old[12:32]=hashlib.sha1(old[32:]).digest()
    struct.pack_into("<I",old,8,zlib.adler32(old[12:])&0xffffffff)
    # Simulate the AOSP metadata relocation; do not generate executable code.
    new=bytearray(old[:144]+struct.pack("<II",8,0)+struct.pack("<I",4))
    for entry in ((0,0,1,0),(6,0,1,112),(0xf000,0,1,144),(0x1000,0,1,152)):
        new.extend(struct.pack("<HHII",*entry))
    struct.pack_into("<I",new,32,len(new))
    struct.pack_into("<I",new,52,152)
    struct.pack_into("<I",new,104,len(new)-144)
    struct.pack_into("<I",new,8,zlib.adler32(new[12:])&0xffffffff)
    return bytes(new)


class HiddenapiObservationTests(unittest.TestCase):
    def test_virtual_original_match(self):
        raw=fixture()
        result=observe(raw)
        self.assertEqual(result["status"],"PRE_HIDDENAPI_SHA1_MATCH_ONLY")
        self.assertTrue(result["stored_sha1_matches_virtual_pre_encoding"])
        self.assertFalse(result["current_sha1_matches"])
        self.assertFalse(result["safe_to_flash"])
        with self.assertRaisesRegex(ValueError,"SHA-1 mismatch"):
            dex_inventory(raw)

    def test_changed_original_body_not_accepted(self):
        raw=bytearray(fixture())
        raw[120]^=1
        struct.pack_into("<I",raw,8,zlib.adler32(raw[12:])&0xffffffff)
        self.assertEqual(observe(raw)["status"],"REVIEW_REQUIRED")

    def test_bad_adler_rejected(self):
        raw=bytearray(fixture())
        raw[120]^=1
        with self.assertRaisesRegex(ValueError,"Adler"):
            observe(raw)

    def test_bad_hiddenapi_bounds(self):
        raw=bytearray(fixture())
        struct.pack_into("<I",raw,144,999)
        struct.pack_into("<I",raw,8,zlib.adler32(raw[12:])&0xffffffff)
        with self.assertRaisesRegex(ValueError,"hiddenapi section bounds"):
            observe(raw)


if __name__=="__main__":
    unittest.main()
