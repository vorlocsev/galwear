"""Synthetic stdlib inventory fixtures; no imports of discovered modules."""
import hashlib
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"build"))
import r800_python_runtime_lock as runtime


class PythonRuntimeTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root=Path(tmp.name)
        (self.root/"module.py").write_text("raise RuntimeError('must not execute')\n")
        (self.root/"empty.py").touch()
        (self.root/"__pycache__").mkdir()
        (self.root/"__pycache__"/"module.pyc").write_bytes(b"fixture-cache")
        (self.root/"lib-dynload").mkdir()
        (self.root/"lib-dynload"/"fixture.so").write_bytes(b"fixture-elf")

    def test_inventory_and_empty(self):
        result=runtime.tree(self.root)
        self.assertEqual(result["file_count"],4)
        self.assertEqual(result["files"]["empty.py"]["sha256"],hashlib.sha256(b"").hexdigest())
        self.assertIn("__pycache__/module.pyc",result["files"])
        self.assertEqual(result["problems"],[])

    def test_changed_source_changes_tree(self):
        before=runtime.tree(self.root)
        (self.root/"module.py").write_text("changed")
        self.assertNotEqual(before["tree_sha256"],runtime.tree(self.root)["tree_sha256"])

    def test_changed_cache_changes_tree(self):
        before=runtime.tree(self.root)
        (self.root/"__pycache__"/"module.pyc").write_bytes(b"new")
        self.assertNotEqual(before["tree_sha256"],runtime.tree(self.root)["tree_sha256"])

    def test_excluded_third_party(self):
        for name in runtime.EXCLUDED:
            (self.root/name).mkdir()
            (self.root/name/"external.py").write_text("external")
        result=runtime.tree(self.root)
        self.assertEqual(result["excluded"],sorted(runtime.EXCLUDED))
        self.assertEqual(result["file_count"],4)

    def test_symlink_not_followed(self):
        (self.root/"alias.py").symlink_to("/nonexistent")
        result=runtime.tree(self.root)
        self.assertEqual(result["files"]["alias.py"],{"kind":"symlink","target":"/nonexistent"})
        self.assertEqual(result["problems"][0]["reason"],"SYMLINK_REQUIRES_REVIEW")

    def test_file_budget(self):
        with patch.object(runtime,"MAX_FILES",2):
            with self.assertRaisesRegex(ValueError,"file budget"):
                runtime.tree(self.root)

    def test_extension_pin_mismatch(self):
        rows=runtime.tree(self.root)["files"]
        name="lib-dynload/fixture.so"
        path=str(self.root/name)
        result={"objects":{path:{"bytes":1,"sha256":"0"*64}},
                "bindings":{name:path},"problems":[],"status":"HOST_STATIC_CANDIDATES_ONLY"}
        with patch.object(runtime,"audit",return_value=result):
            report=runtime.extensions(self.root,rows)
        self.assertEqual(report["status"],"HOST_REVIEW_REQUIRED")
        self.assertIn("EXTENSION_PIN_MISMATCH",[p["reason"] for p in report["problems"]])

    def test_no_extension_requires_review(self):
        (self.root/"lib-dynload"/"fixture.so").unlink()
        report=runtime.extensions(self.root,runtime.tree(self.root)["files"])
        self.assertEqual(report["status"],"HOST_REVIEW_REQUIRED")


if __name__=="__main__":
    unittest.main()
