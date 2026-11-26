"""Synthetic orchestration tests; no real NDK or donor execution."""
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "build"))
import r800_gps_xtra_matrix as target


def result(abi):
    run = {"binary_sha256": str(abi) * 64,
           "donor_sha256": {"fixture": "same"},
           "input_fingerprints": {"source": "same"},
           "compiler_argv": ["clang", "-DR800_XTRA_ABI=" + str(abi)]}
    return {"schema": "galwear-r800-gps-repeatability-v1",
            "status": "LOCAL_REPEATABILITY_PASS", "differences": [],
            "runs": [dict(run), dict(run)], "xtra_abi": abi,
            "runtime_verified": False, "independent_hosts_tested": False,
            "safe_to_flash": False}


class MatrixTests(unittest.TestCase):
    def run_matrix(self, responses):
        with patch.object(target, "compare", side_effect=responses) as compare:
            report = target.matrix(Path("builder"), Path("ndk"), Path("donor"), 7)
        self.assertEqual([call.args[3] for call in compare.call_args_list], [0, 1, 2])
        self.assertTrue(all(call.kwargs == {"timeout": 7}
                            for call in compare.call_args_list))
        self.assertIsNone(report["selected_abi"])
        self.assertFalse(report["runtime_verified"])
        self.assertFalse(report["safe_to_flash"])
        self.assertTrue(all(row["runtime_compatibility"] == "NOT_TESTED"
                            for row in report["modes"]))
        return report

    def test_all_pass(self):
        report = self.run_matrix([result(i) for i in range(3)])
        self.assertEqual(report["status"], "LOCAL_MATRIX_PASS")
        self.assertEqual(report["passed_modes"], 3)

    def test_failure_does_not_skip_other_modes(self):
        for exc in (ValueError("link error"), subprocess.TimeoutExpired("sh", 7)):
            with self.subTest(exc=exc):
                report = self.run_matrix([result(0), exc, result(2)])
                self.assertEqual(report["status"], "LOCAL_MATRIX_FAIL")
                self.assertEqual(report["passed_modes"], 2)

    def test_wrong_abi(self):
        report = self.run_matrix([result(0), result(0), result(2)])
        self.assertEqual(report["passed_modes"], 2)

    def test_wrong_compiler_flag(self):
        wrong = result(1)
        wrong["runs"][1]["compiler_argv"] = ["clang", "-DR800_XTRA_ABI=0"]
        report = self.run_matrix([result(0), wrong, result(2)])
        self.assertEqual(report["passed_modes"], 2)

    def test_inconsistent_pass(self):
        wrong = result(1)
        wrong["runs"][1]["binary_sha256"] = "changed"
        report = self.run_matrix([result(0), wrong, result(2)])
        self.assertEqual(report["passed_modes"], 2)

    def test_runtime_claim_rejected(self):
        wrong = result(1)
        wrong["runtime_verified"] = True
        report = self.run_matrix([result(0), wrong, result(2)])
        self.assertEqual(report["passed_modes"], 2)

    def test_cross_mode_input_changes(self):
        for field in ("donor_sha256", "input_fingerprints"):
            with self.subTest(field=field):
                wrong = result(1)
                for run in wrong["runs"]:
                    run[field] = {"changed": True}
                report = self.run_matrix([result(0), wrong, result(2)])
                self.assertEqual(report["passed_modes"], 3)
                self.assertEqual(report["status"], "LOCAL_MATRIX_FAIL")
                self.assertEqual(report["cross_mode_differences"],
                                 [{"abi": 1, "field": field}])


if __name__ == "__main__":
    unittest.main()
