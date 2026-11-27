import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import struct

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "build"))
import r800_aosp_checkfc_matrix as m


class AospCheckfcMatrixTests(unittest.TestCase):
    def test_stock_selected_modes_and_negative_contract(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            product = root/"product"
            def put(rel, raw):
                path = product/rel
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(raw)
            put("vendor/etc/selinux/precompiled_sepolicy",
                struct.pack("<II8sIIII", 0xf97cff8c, 8, b"SE Linux", 31, 1, 8, 8))
            for kind in m.REQUIRED:
                put("system/etc/selinux/plat_" + m.KINDS[kind],
                    b"fixture u:object_r:fixture_t:s0\n")
            tool = root/"checkfc"
            tool.write_bytes(b"mock tool")
            def fake(policy, tool, digest, entries):
                kind, path, expected = entries[0]
                code = int(path.name == "negative.contexts")
                return {"checks": [{"kind": kind, "sha256": expected,
                                    "status": "REVIEW_REQUIRED" if code else "PASS",
                                    "exit_code": code}]}
            with patch.object(m, "audit_checkfc", side_effect=fake):
                report = m.audit(product, tool)
                self.assertEqual(report["status"], "AOSP_CHECKFC_STOCK_CONTEXTS_ONLY")
                self.assertFalse(report["vndservice_present"])
                self.assertFalse(report["donor_policy_verified"])
                (product/"system/etc/selinux/plat_hwservice_contexts").unlink()
                report = m.audit(product, tool)
                self.assertEqual(report["missing_required_modes"], ["hwservice"])
                self.assertEqual(report["status"], "REVIEW_REQUIRED")
                self.assertFalse(report["safe_to_flash"])


if __name__ == "__main__":
    unittest.main()
