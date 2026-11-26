"""Synthetic transcript tests. No QEMU or donor code execution."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "build"))
from r800_gps_qemu_evidence import DONORS, LABELS, MARKERS, MAX_LOG, evaluate


class QemuEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.inputs = {name: str(i + 1) * 64 for i, name in enumerate(LABELS)}
        self.audit = {"status": "STATIC_GLIBC_CLOSURE_ONLY", "static_closure_pass": True,
                      "safe_to_flash": False, "runtime_verified": False, "problems": [],
                      "sha256": self.inputs["probe"],
                      "donor_sha256": {name: self.inputs[name] for name in DONORS}}
        self.lines = [name + "=PASS" for name in MARKERS]

    def review(self, lines=None, rc=0, after=None, audit=None):
        raw = ("\n".join(self.lines if lines is None else lines) + "\n").encode()
        return evaluate(raw, rc, self.inputs, self.inputs if after is None else after,
                        self.audit if audit is None else audit)

    def test_exact_complete_transcript(self):
        report = self.review()
        self.assertEqual(report["status"], "QEMU_GLIBC_PROBE_PASS")
        self.assertEqual(report["observed_ordered_markers"], list(MARKERS))
        self.assertFalse(report["safe_to_flash"])
        self.assertFalse(report["gnss_runtime_verified"])

    def test_partial_and_empty(self):
        for count in range(len(MARKERS)):
            report = self.review(self.lines[:count])
            self.assertIn("INCOMPLETE_OR_UNEXPECTED_TRANSCRIPT", report["problems"])
            self.assertEqual(report["observed_ordered_markers"], list(MARKERS[:count]))

    def test_duplicate_reordered_contradictory(self):
        for lines in (self.lines + [self.lines[-1]], self.lines[::-1],
                      self.lines + [MARKERS[0] + "=FAIL"]):
            self.assertIn("MARKER_SEQUENCE", self.review(lines)["problems"])

    def test_unexpected_diagnostic_after_pass(self):
        self.assertIn("INCOMPLETE_OR_UNEXPECTED_TRANSCRIPT",
                      self.review(self.lines + ["loader warning"])["problems"])

    def test_timeout_and_nonzero(self):
        for code in (124, 137, 15, 126):
            report = self.review(rc=code)
            self.assertEqual(report["status"], "QEMU_GLIBC_PROBE_REVIEW_REQUIRED")
            self.assertIn("TIMEOUT_OR_KILLED" if code in (124, 137) else "NONZERO_EXIT",
                          report["problems"])

    def test_every_artifact_identity(self):
        for name in LABELS:
            self.assertIn("INPUT_IDENTITY", self.review(after=dict(self.inputs, **{name: "0" * 64}))["problems"])

    def test_link_evidence_binding(self):
        for changed in (dict(self.audit, sha256="0" * 64), dict(self.audit, donor_sha256={}),
                        dict(self.audit, safe_to_flash=True), dict(self.audit, problems=["failure"])):
            self.assertIn("STATIC_LINK_EVIDENCE", self.review(audit=changed)["problems"])

    def test_invalid_transcript_and_status(self):
        for raw, code in ((b"x" * (MAX_LOG + 1), 0), (b"", True), (b"", 256), (b"\xff", 0)):
            with self.assertRaises(ValueError):
                evaluate(raw, code, self.inputs, self.inputs, self.audit)


if __name__ == "__main__":
    unittest.main()
