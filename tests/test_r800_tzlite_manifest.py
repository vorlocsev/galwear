"""Integrity verification of isolated static tree metadata and files."""
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"build"))
import r800_tzlite_manifest as m


class ManifestTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root=Path(tmp.name)
        self.lib=self.root/"lib"
        self.lib.mkdir()
        self.file=self.lib/"real.so"
        self.file.write_bytes(b"fixture")
        self.file.chmod(0o644)
        self.alias=self.lib/"alias.so"
        self.alias.symlink_to("real.so")
        self.path=self.root/m.MANIFEST
        self.report={"schema":"r800-tzlite-static-stage-v2",
                     "status":"TZLITE_STATIC_CANDIDATE_ONLY",
                     "tree":m.inventory(self.root),"source_and_stage_audited":True,
                     "full_configuration_copied":False,"plugins_complete":False,
                     "ownership_preserved":False,"runtime_verified":False,"safe_to_flash":False}
        self.path.write_text(json.dumps(self.report))
        self.digest=hashlib.sha256(self.path.read_bytes()).hexdigest()

    def check(self):
        return m.verify(self.root,self.digest)

    def test_valid(self):
        result=self.check()
        self.assertEqual(result["status"],"STATIC_TREE_INTEGRITY_ONLY")
        self.assertEqual(result["entries"],3)
        self.assertFalse(result["runtime_verified"])
        self.assertFalse(result["safe_to_flash"])

    def test_modified_file(self):
        self.file.write_bytes(b"changed")
        with self.assertRaises(ValueError): self.check()

    def test_mode_changed(self):
        self.file.chmod(0o755)
        with self.assertRaises(ValueError): self.check()

    def test_directory_mode_changed(self):
        self.lib.chmod(0o700)
        with self.assertRaises(ValueError): self.check()

    def test_extra_file(self):
        (self.root/"extra").write_bytes(b"")
        with self.assertRaises(ValueError): self.check()

    def test_missing_file(self):
        self.file.unlink()
        with self.assertRaises(ValueError): self.check()

    def test_link_escape(self):
        self.alias.unlink()
        self.alias.symlink_to("../../outside")
        with self.assertRaises(ValueError): self.check()

    def test_absolute_link(self):
        self.alias.unlink()
        self.alias.symlink_to(self.file)
        with self.assertRaises(ValueError): self.check()

    def test_hardlink(self):
        os.link(self.file,self.root/"duplicate")
        with self.assertRaises(ValueError): self.check()

    def test_fifo(self):
        os.mkfifo(self.root/"fifo")
        with self.assertRaises(ValueError): self.check()

    def test_wrong_manifest_hash(self):
        self.path.write_text("{}")
        with self.assertRaises(ValueError): self.check()

    def test_manifest_symlink(self):
        real=self.root/"other"
        self.path.rename(real)
        self.path.symlink_to(real)
        with self.assertRaises(OSError): self.check()


if __name__=="__main__":
    unittest.main()
