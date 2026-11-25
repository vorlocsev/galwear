"""Regression checks of input boundaries and executable Python CLI imports."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

BUILD = Path(__file__).resolve().parents[1]/"build"
sys.path.insert(0,str(BUILD))
from r800_android_init_dependencies import regular
from r800_qemu_guest_abi import read_bounded_json, unique_evidence_object
from r800_android_system_ext4 import system_entries

class EvidenceBoundaryTests(unittest.TestCase):
    def test_regular_path_boundaries(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)/"root"
            root.mkdir()
            outside=Path(tmp)/"outside"
            outside.write_bytes(b"outside")
            inside=root/"inside"
            inside.write_bytes(b"inside")
            (root/"alias").symlink_to(outside)
            self.assertEqual(regular(root,"inside"),inside)
            for rel in (str(outside),"../outside","./inside","alias","", "missing"):
                with self.subTest(rel=rel):
                    self.assertIsNone(regular(root,rel))

    def test_reject_symlink_parent_and_loop(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            (root/"real").mkdir()
            (root/"real/file").write_bytes(b"x")
            (root/"alias").symlink_to(root/"real",target_is_directory=True)
            (root/"loop").symlink_to(root/"loop")
            self.assertIsNone(regular(root,"alias/file"))
            self.assertIsNone(regular(root,"loop"))

    def test_duplicate_top_level_and_nested_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/"evidence.json"
            for raw in ('{"status":"PASS","status":"REJECT"}',
                        '{"init":{"sha256":"one","sha256":"two"}}'):
                path.write_text(raw)
                with self.assertRaisesRegex(ValueError,"Duplicate evidence key"):
                    read_bounded_json(path)
            path.write_text('{"init":{"sha256":"one"}}')
            self.assertEqual(read_bounded_json(path),{"init":{"sha256":"one"}})

    def test_duplicate_baseline_decoder(self):
        with self.assertRaisesRegex(ValueError,"Duplicate evidence key"):
            json.loads('{"safe_to_flash":true,"safe_to_flash":false}',
                       object_pairs_hook=unique_evidence_object)

    def test_noncanonical_system_entries(self):
        for name in ("system//bin/file","system/./bin/file","system/../file"):
            with self.subTest(name=name):
                with self.assertRaisesRegex(ValueError,"Unexpected system entry"):
                    system_entries([(name,(0o100644,b"x",0,0))],{})

    def test_cli_import_and_help(self):
        # Real subprocesses: no mocking of imports or argparse.
        for name in ("r800_android_system_ext4","r800_android_context_partitions",
                     "r800_android_apex_payload","r800_qemu_readonly_disks",
                     "r800_qemu_block_smoke","r800_qemu_prelabeled_mounts",
                     "r800_qemu_ext4_init_transition","r800_qemu_ext4_property_service",
                     "r800_ext4_property_pipeline","r800_property_pipeline"):
            with self.subTest(name=name):
                result=subprocess.run([sys.executable,str(BUILD/(name+".py")),"--help"],
                                      capture_output=True,text=True,timeout=15)
                self.assertEqual(result.returncode,0,result.stderr)
                self.assertIn("usage:",result.stdout)

if __name__=="__main__":
    unittest.main()
