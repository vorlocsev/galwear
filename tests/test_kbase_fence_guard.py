"""Offline fence source extraction and guard regression."""
import sys
from pathlib import Path
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"build"))
import r800_kbase_fence_guard as mod

class KbaseFenceGuardTests(unittest.TestCase):
    def test_guard_matches_legacy_get(self):
        self.assertIn("#if (KERNEL_VERSION(4, 9, 67) >= LINUX_VERSION_CODE)",mod.NEW)
        self.assertIn("#endif\n\t\tkbase_fence_out_remove(katom);",mod.NEW)

    def test_missing_function(self):
        with self.assertRaises(ValueError):
            mod.function("bad","int kbase_sync_fence_out_create(")
