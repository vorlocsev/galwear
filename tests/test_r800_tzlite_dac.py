"""Conditional DAC precedence and canonical parent traversal."""
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"build"))
from r800_tzlite_dac import acl_bits, mode_bits, inode_candidate, canonical_path_candidate, identity_candidates

GROUPS={1:[(7,0xffffffff)],2:[(6,5001)],4:[(4,0xffffffff)],
        8:[(3,5002)],16:[(5,0xffffffff)],32:[(7,0xffffffff)]}


class DacTests(unittest.TestCase):
    def test_owner_precedence(self):
        self.assertEqual(acl_bits(GROUPS,(5001,5002),5001,5002),(7,"owner"))
    def test_named_user_mask_no_fallback(self):
        self.assertEqual(acl_bits(GROUPS,(5001,5002),1000,5002),(4,"named_user"))
    def test_matching_group_individual_bits(self):
        self.assertEqual(acl_bits(GROUPS,(6000,5002),1000,5002),(5,"matching_groups"))
    def test_other_class(self):
        self.assertEqual(acl_bits(GROUPS,(6000,6000),1000,5002),(7,"other"))
    def test_mode_classes(self):
        self.assertEqual(mode_bits(0o740,(5001,5002),5001,1),(7,"owner"))
        self.assertEqual(mode_bits(0o740,(5001,5002),1,5002),(4,"owning_group"))
        self.assertEqual(mode_bits(0o740,(5001,5002),1,1),(0,"other"))
    def test_unknown_acl_absence(self):
        record={"kind":"regular","mode":"0o755","uid":1,"gid":1,
                "xattr_inventory":{"attributes":{}}}
        self.assertEqual(inode_candidate(record,(5001,5002))["status"],
                         "MODE_ONLY_ACL_ABSENCE_UNVERIFIED")
    def test_inconsistent_acl(self):
        record={"kind":"regular","xattr_inventory":{"attributes":{
            "system.posix_acl_access":{"structure":{"mode_consistent":False}}}}}
        self.assertEqual(inode_candidate(record,(5001,5002))["status"],"REVIEW_REQUIRED_ACL")
    def test_parent_traversal(self):
        def item(kind,bits):
            return {"kind":kind,"dac_candidate":{"permission_bits":bits,
                    "status":"MODE_ONLY_ACL_ABSENCE_UNVERIFIED"}}
        entries={"/":item("directory",7),"/usr":item("directory",6),
                 "/usr/file":item("regular",7)}
        result=canonical_path_candidate(entries,"/usr/file",4)
        self.assertEqual(result["status"],"DENIED_CANDIDATE")
        self.assertEqual(result["denied_paths"],["/usr"])
        entries["/usr"]=item("directory",1)
        self.assertEqual(canonical_path_candidate(entries,"/usr/file",4)["status"],
                         "CONDITIONAL_MODE_CANDIDATE")
        del entries["/usr"]
        self.assertEqual(canonical_path_candidate(entries,"/usr/file",4)["status"],"REVIEW_REQUIRED")
    def test_nonroot_identity(self):
        self.assertEqual(identity_candidates({"uid_candidate":5001,"primary_gid_candidate":5002}),(5001,5002))
        for uid in (0,True,None,-1):
            with self.assertRaises(ValueError):
                identity_candidates({"uid_candidate":uid,"primary_gid_candidate":5002})


if __name__=="__main__":
    unittest.main()
