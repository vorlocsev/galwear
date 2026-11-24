"""Synthetic logs only; no device or firmware."""
import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "build"))
import r800_graphics_trace as audit


class GraphicsTraceTests(unittest.TestCase):
    def test_all_fault_classes(self):
        events, unknown = audit.kernel_events(
            "[1.0] sysmmu page fault\n[2.0] fence wait timeout\n"
            "[3.0] decon underrun\n[4.0] dsim line count 0\n[5.0] mali GPU fault\n")
        self.assertEqual([e["kinds"][0] for e in events],
                         ["iommu_fault", "fence_wait", "decon_timeout", "dsim_timeout", "gpu_fault"])
        self.assertEqual(unknown, 0)

    def test_correlated_interval_not_hardware_proof(self):
        out = audit.audit("[ 13.0] fence wait timeout\n", "10 42\n13 42\n16 42\n19 43\n")
        self.assertEqual(out["no_frame_intervals"],
                         [{"start_s": 10, "end_s": 16, "coincident_event_indices": [0]}])
        self.assertFalse(out["display_active_state_verified"])
        self.assertFalse(out["zero_copy_correctness_verified"])
        self.assertFalse(out["safe_to_flash"])

    def test_missing_samples_not_stall(self):
        self.assertEqual(audit.gaps([(1, 2), (20, 2)]), [])

    def test_active_frames(self):
        self.assertEqual(audit.gaps([(1, 2), (4, 3), (7, 4)]), [])

    def test_short_idle(self):
        self.assertEqual(audit.gaps([(1, 2), (4, 2)]), [])

    def test_counter_reset_or_duplicate_timestamp(self):
        for s in ("1 10\n4 9", "1 10\n1 10", "4 10\n1 10"):
            with self.subTest(s=s), self.assertRaises(ValueError):
                audit.frame_samples(s)

    def test_kernel_clock_regression(self):
        with self.assertRaises(ValueError):
            audit.kernel_events("[12] fence timeout\n[1] mali fault")

    def test_unparsed_events_not_correlated(self):
        out = audit.audit("decon timeout", "1 2\n4 2\n7 2")
        self.assertEqual(out["unparsed_matching_lines"], 1)
        self.assertFalse(out["no_frame_intervals"][0]["coincident_event_indices"])

    def test_invalid_sample(self):
        with self.assertRaises(ValueError):
            audit.frame_samples("1 2 extra")


if __name__ == "__main__":
    unittest.main()
