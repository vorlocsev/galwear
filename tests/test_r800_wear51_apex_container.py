"""Bounded original_apex wrapper tests without proprietary images."""
import hashlib
import io
from pathlib import Path
import sys
import unittest
import warnings
import zipfile
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"build"))
from r800_wear51_apex_container import inspect_container

MODULE="com.android.art"

def archive(entries):
    b=io.BytesIO()
    with zipfile.ZipFile(b,"w",compression=zipfile.ZIP_DEFLATED) as z:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            for name,data in entries:
                z.writestr(name,data)
    return b.getvalue()

def manifest(name=MODULE):
    return b'\x0a'+bytes([len(name)])+name.encode()+b'\x10\x01'

class Wear51ApexContainerTests(unittest.TestCase):
    def test_direct_observation(self):
        raw=archive([("apex_payload.img",b"fixture")])
        r,n=inspect_container(raw,MODULE)
        self.assertIsNone(n)
        self.assertEqual(r["layout"],"DIRECT_OR_UNRECOGNIZED")
        self.assertFalse(r["safe_to_flash"])

    def test_nested_wrapper(self):
        nested=archive([("apex_payload.img",b"fixture")])
        raw=archive([("original_apex",nested),("apex_manifest.pb",manifest())])
        r,n=inspect_container(raw,MODULE)
        self.assertEqual(n,nested)
        self.assertEqual(r["nested_sha256"],hashlib.sha256(nested).hexdigest())
        self.assertEqual(r["wrapper_identity"],{"name":MODULE,"version":1})

    def test_wrong_identity(self):
        nested=archive([("apex_payload.img",b"fixture")])
        raw=archive([("original_apex",nested),("apex_manifest.pb",manifest("com.android.runtime"))])
        with self.assertRaisesRegex(ValueError,"identity"):
            inspect_container(raw,MODULE)

    def test_ambiguous_payload(self):
        raw=archive([("original_apex",b"nested"),("apex_payload.img",b"direct")])
        with self.assertRaisesRegex(ValueError,"Ambiguous"):
            inspect_container(raw,MODULE)

    def test_duplicate_or_traversal(self):
        for entries in ([("original_apex",b"1"),("original_apex",b"2")],
                        [("../original_apex",b"data")]):
            with self.assertRaises(ValueError):
                inspect_container(archive(entries),MODULE)

    def test_missing_manifest(self):
        with self.assertRaisesRegex(ValueError,"identity"):
            inspect_container(archive([("original_apex",b"not an apex")]),MODULE)

if __name__=="__main__":
    unittest.main()
