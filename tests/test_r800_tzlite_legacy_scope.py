"""Filesystem legacy scope tests; no source copier import or execution."""
import ast
import hashlib
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"build"))
import r800_tzlite_legacy_scope as scope


class LegacyScopeTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root=Path(tmp.name)/"root"
        self.root.mkdir()
        for name in scope.FILES:
            path=self.root/name.lstrip("/")
            path.parent.mkdir(parents=True,exist_ok=True)
            path.write_bytes(b"fixture")
        for name in scope.REQUIRED_TREES:
            (self.root/name.lstrip("/")).mkdir(parents=True,exist_ok=True)
        for name in scope.LINKS:
            (self.root/name.lstrip("/")).symlink_to("usr/lib")

    def test_legacy_list_parity(self):
        script=Path(__file__).resolve().parents[1]/"src/tools/tzlite/mktzlite.py"
        assignments={}
        for stmt in ast.parse(script.read_text()).body:
            if isinstance(stmt,ast.Assign) and len(stmt.targets)==1 and isinstance(stmt.targets[0],ast.Name):
                name=stmt.targets[0].id
                if name in ("FILES","LIBS","TREES","LINKS"):
                    assignments[name]=ast.literal_eval(stmt.value)
        self.assertEqual(set(scope.FILES),set(assignments["FILES"])|{"/usr/lib/gconv/gconv-modules.cache"})
        self.assertIn("/usr/lib/gconv/gconv-modules.cache",assignments["LIBS"])
        self.assertEqual(tuple(assignments["TREES"]),scope.REQUIRED_TREES)
        self.assertEqual(tuple(assignments["LINKS"]),scope.LINKS)

    def test_tree_and_hash(self):
        path=self.root/"usr/lib/sensor/plugin.so"
        path.write_bytes(b"\x7fELFsynthetic")
        result=scope.inspect(self.root)
        self.assertIn("/usr/lib/sensor/plugin.so",result["elf_candidates"])
        self.assertEqual(result["entries"]["/usr/lib/sensor/plugin.so"]["sha256"],
                         hashlib.sha256(path.read_bytes()).hexdigest())
        self.assertIn("/etc/nsswitch.conf",result["outside_four_config_baseline"])
        self.assertFalse(result["files_copied"])

    def test_no_external_symlink_traversal(self):
        external=self.root.parent/"outside"
        external.mkdir()
        (external/"secret").write_bytes(b"not donor")
        (self.root/"usr/lib/sensor/escape").symlink_to(external)
        report=scope.inspect(self.root)
        self.assertIn("SYMLINK_REVIEW:/usr/lib/sensor/escape",report["problems"])
        self.assertFalse(any("secret" in name for name in report["entries"]))
        self.assertFalse(report["symlinks_followed"])

    def test_parent_symlink(self):
        parent=self.root/"usr/etc"
        (parent/"sensor.xml").unlink()
        parent.rmdir()
        parent.symlink_to("/etc")
        report=scope.inspect(self.root)
        self.assertIn("PARENT_REVIEW:/usr/etc/sensor.xml",report["problems"])
        self.assertNotIn("/usr/etc/sensor.xml",report["entries"])

    def test_missing_config(self):
        (self.root/"etc/hosts").unlink()
        self.assertIn("MISSING:/etc/hosts",scope.inspect(self.root)["problems"])

    def test_special_and_hardlink(self):
        os.mkfifo(self.root/"usr/lib/sensor/fifo")
        os.link(self.root/"etc/passwd",self.root/"usr/lib/sensor/hard")
        report=scope.inspect(self.root)
        self.assertIn("SPECIAL_OBJECT_REVIEW:/usr/lib/sensor/fifo",report["problems"])
        self.assertIn("HARDLINK_REVIEW:/usr/lib/sensor/hard",report["problems"])
        self.assertNotIn("sha256",report["entries"]["/usr/lib/sensor/hard"])

    def test_entry_budget(self):
        with patch.object(scope,"MAX_ENTRIES",2):
            with self.assertRaises(ValueError):
                scope.inspect(self.root)

    def test_byte_budget(self):
        with patch.object(scope,"MAX_TOTAL",3):
            with self.assertRaises(ValueError):
                scope.inspect(self.root)

    def test_symlink_root(self):
        alias=self.root.parent/"alias"
        alias.symlink_to(self.root)
        with self.assertRaises(ValueError):
            scope.inspect(alias)


if __name__=="__main__":
    unittest.main()
