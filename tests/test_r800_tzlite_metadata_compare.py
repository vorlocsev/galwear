"""Compare source metadata and staged access candidates without privilege changes."""
from pathlib import Path
import sys
import tempfile
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"build"))
from r800_tzlite_manifest import inventory
from r800_tzlite_metadata_compare import staged_metadata, staged_path, metadata_differences, compare_access


class CompareTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root=Path(tmp.name)
        self.root.chmod(0o700)
        (self.root/"usr").mkdir(mode=0o755)
        (self.root/"usr/file").write_bytes(b"fixture")
        (self.root/"usr/file").chmod(0o644)
        (self.root/"lib").mkdir(mode=0o755)
        (self.root/"lib/alias").symlink_to("../usr/file")
        self.tree=inventory(self.root)
        self.identity=(self.root.stat().st_uid+10001,self.root.stat().st_gid+10001)

    def metadata(self):
        return staged_metadata(self.root,self.tree,self.identity)

    def test_root_search_denied(self):
        data=self.metadata()
        result=staged_path(data,"/usr/file","/usr/file",4)
        self.assertEqual(result["status"],"DENIED_CANDIDATE")
        self.assertIn("/",result["denied_paths"])

    def test_alias_search_denied(self):
        result=staged_path(self.metadata(),"/lib/alias","/usr/file",4)
        self.assertEqual(result["status"],"DENIED_CANDIDATE")
        self.assertIn("/",result["denied_paths"])

    def test_changed_mode_rejected(self):
        (self.root/"usr/file").chmod(0o600)
        with self.assertRaises(ValueError):
            self.metadata()

    def test_changed_alias_rejected(self):
        alias=self.root/"lib/alias"
        alias.unlink()
        alias.symlink_to("../other")
        with self.assertRaises(ValueError):
            self.metadata()

    def test_mismatched_canonical(self):
        self.assertEqual(staged_path(self.metadata(),"/lib/alias","/usr/other",4)["status"],
                         "REVIEW_REQUIRED")

    def test_metadata_differences(self):
        staged=self.metadata()
        original={"/usr/file":dict(staged["/usr/file"],mode="0o4755",
                    xattr_inventory={"attributes":{"security.capability":{}}})}
        changes=metadata_differences(original,staged)
        self.assertEqual(changes["/usr/file"]["fields"]["mode"]["original"],"0o4755")
        self.assertIn("security.capability",changes["/usr/file"]["reported_original_xattrs_not_staged"])
        self.assertEqual(changes["/"]["status"],"STAGED_ONLY")

    def test_comparison_not_permission_authorization(self):
        staged=self.metadata()
        report=compare_access({},staged,{"files":{"/usr/file":{"read":{
            "status":"CONDITIONAL_MODE_CANDIDATE","requested_bit":4}}},"aliases":{}},{"aliases":{}})
        self.assertEqual(report["access_comparison"]["files"]["/usr/file"]["read"]["status"],
                         "DIFFERENT_CANDIDATE")
        self.assertFalse(report["permission_changes_applied"])
        self.assertFalse(report["safe_to_flash"])


if __name__=="__main__":
    unittest.main()
