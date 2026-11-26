"""Synthetic static-readiness evidence contract; not runtime verification."""
from pathlib import Path
import copy
import hashlib
import json
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/"build"))
from r800_gps_static_readiness import evaluate, RUNTIME_FLAGS
from r800_gps_donor_snapshot import DONORS
from r800_gps_repeatability import normalize_argv


class StaticReadinessTests(unittest.TestCase):
    def records(self):
        hashes = {name: "a"*64 for name in DONORS}
        link = {"status": "STATIC_GLIBC_CLOSURE_ONLY", "static_closure_pass": True,
                "problems": [], "runtime_verified": False, "safe_to_flash": False,
                "sha256": "b"*64, "donor_sha256": hashes}
        preflight = {"status": "TIZEN_GNSS_STATIC_ONLY", "strict_4k_page_review": True,
                     "problems": [], "closure_problems": [],
                     **dict.fromkeys(RUNTIME_FLAGS, False)}
        archive = {"status": "TIZEN_ELF_ARCHIVE_STATIC_ONLY", "strict_4k_page_review": True,
                   "runtime_verified": False, "safe_to_flash": False, "sha256": "c"*64,
                   "donor_bindings": {name: {"sha256": h} for name, h in hashes.items()}}
        inputs = {"schema": "galwear-r800-gps-inputs-v1", "safe_to_flash": False,
                  "signed_attestation": False, "inputs": {"source": {"sha256": "d"*64}},
                  "argv": ["/ndk/clang", "-DR800_XTRA_ABI=0", "-o", "/tmp/stage/gpsbridge"]}
        build = {"schema": "galwear-r800-gps-evidence-v1", "safe_to_flash": False,
                 "signed_attestation": False, "binary_sha256": link["sha256"],
                 "donor_sha256": hashes, "tizen_archive": archive, "inputs": inputs,
                 "inputs_sha256": hashlib.sha256(json.dumps(inputs, sort_keys=True).encode()).hexdigest()}
        run = {"binary_sha256": link["sha256"], "donor_sha256": hashes,
               "input_fingerprints": inputs["inputs"], "compiler_argv": normalize_argv(inputs["argv"]),
               "tizen_archive": archive}
        repeat = {"schema": "galwear-r800-gps-repeatability-v1", "status": "LOCAL_REPEATABILITY_PASS",
                  "differences": [], "independent_hosts_tested": False, "runtime_verified": False,
                  "safe_to_flash": False, "runs": [run, run], "xtra_abi": 0}
        return [copy.deepcopy(x) for x in (link, preflight, archive, build, repeat, inputs)]

    def test_matching_static_evidence_is_not_flash_permission(self):
        report = evaluate(*self.records())
        self.assertEqual(report["status"], "GPS_STATIC_EVIDENCE_MATCH")
        self.assertTrue(report["static_evidence_match"])
        for flag in ("runtime_verified", "hardware_verified", "safe_to_flash", "signed_attestation"):
            self.assertFalse(report[flag])

    def test_contradictory_evidence(self):
        for index, key, value, label in (
                (0, "static_closure_pass", False, "LINK_AUDIT"),
                (0, "problems", ["missing"], "LINK_AUDIT"),
                (1, "strict_4k_page_review", False, "GNSS_PREFLIGHT"),
                (1, "gnss_fix_verified", True, "GNSS_PREFLIGHT"),
                (1, "closure_problems", ["missing"], "GNSS_PREFLIGHT"),
                (2, "donor_bindings", {}, "ARCHIVE_DONORS"),
                (3, "tizen_archive", None, "BUILD_PROVENANCE"),
                (3, "binary_sha256", "0"*64, "BUILD_PROVENANCE"),
                (3, "inputs_sha256", "0"*64, "BUILD_PROVENANCE"),
                (4, "runs", [], "LOCAL_REPEATABILITY"),
                (4, "xtra_abi", True, "LOCAL_REPEATABILITY"),
                (4, "xtra_abi", 1, "LOCAL_REPEATABILITY"),
                (5, "inputs", {}, "BUILD_PROVENANCE")):
            with self.subTest(index=index, key=key):
                records = self.records()
                records[index][key] = value
                result = evaluate(*records)
                self.assertEqual(result["status"], "REVIEW_REQUIRED")
                self.assertIn(label, result["problems"])
                self.assertFalse(result["safe_to_flash"])

    def test_second_run_must_match_exact_record(self):
        records = self.records()
        records[4]["runs"][1] = dict(records[4]["runs"][1], binary_sha256="0"*64)
        self.assertIn("LOCAL_REPEATABILITY", evaluate(*records)["problems"])


if __name__ == "__main__":
    unittest.main()
