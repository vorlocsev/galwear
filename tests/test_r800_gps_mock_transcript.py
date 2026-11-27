"""Synthetic log fixtures only; no QEMU or physical HAL execution."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "build"))
from r800_gps_mock_transcript import evaluate, MAX_LOG

HEAD = "GpsInterface 0x1234abcd size 40\n"
INIT = HEAD + "CAPS 1234\ninit 0\ninject_time 1700000000000 ref 1234 unc 500 -> 0\n"
START = INIT + "set_position_mode 0\nSTATUS 1\nFIX flags=1f lat=12.5000000 lon=-34.2500000 alt=100.0 spd=1.50 brg=90.0 acc=5.0 t=1700000000000\nNMEA $GPGGA,MOCK*00\nstart 0 (running 0 s)\n"
LOGS = (START + "STATUS 2\nstop 0\nCAPS 4321\n", HEAD + "init -11\n",
        INIT + "set_position_mode -12\nCAPS 4321\n",
        INIT + "set_position_mode 0\nstart -13 (running 0 s)\nCAPS 4321\n",
        START + "stop -14\nCAPS 4321\n")


class MockTranscriptTests(unittest.TestCase):
    def test_all_five_scenarios(self):
        for stage, log in enumerate(LOGS):
            with self.subTest(stage=stage):
                result = evaluate(log.encode(), stage, int(stage != 0))
                self.assertEqual(result["status"], "MOCK_HAL_TRANSCRIPT_MATCH")
                self.assertFalse(result["vendor_abi_verified"])
                self.assertFalse(result["gnss_runtime_verified"])
                self.assertFalse(result["safe_to_flash"])

    def test_wrong_exit_status(self):
        for stage, log in enumerate(LOGS):
            self.assertIn("EXIT_STATUS_MISMATCH", evaluate(log.encode(), stage, int(stage == 0))["problems"])

    def test_timeout(self):
        self.assertIn("EXIT_STATUS_MISMATCH", evaluate(LOGS[0].encode(), 0, 124)["problems"])

    def test_missing_cleanup(self):
        for stage in (0, 2, 3, 4):
            raw = LOGS[stage].replace("CAPS 4321\n", "").encode()
            self.assertIn("TRANSCRIPT_MISMATCH", evaluate(raw, stage, int(stage != 0))["problems"])

    def test_invalid_callbacks_or_xtra(self):
        for extra in ("CAPS dead\n", "STATUS 99\n", "NMEA $GPGGA,BAD\nFRAME\n", "FIX unexpected\n"):
            self.assertIn("TRANSCRIPT_MISMATCH", evaluate((LOGS[0]+extra).encode(), 0, 0)["problems"])

    def test_wrong_order_and_wrong_fix(self):
        for log in (LOGS[0].replace("STATUS 2\nstop 0", "stop 0\nSTATUS 2"),
                    LOGS[0].replace("lat=12.5000000", "lat=13.5000000")):
            self.assertIn("TRANSCRIPT_MISMATCH", evaluate(log.encode(), 0, 0)["problems"])

    def test_failed_stage_cannot_hide_start(self):
        raw = (LOGS[2]+"start -94 (running 0 s)\n").encode()
        self.assertIn("TRANSCRIPT_MISMATCH", evaluate(raw, 2, 1)["problems"])

    def test_bounds_and_types(self):
        for raw, stage, rc in ((b"x"*(MAX_LOG+1), 0, 0), (b"", 5, 0),
                               (b"", False, 0), (b"", 0, True), (b"\xff", 0, 0)):
            with self.assertRaises(ValueError):
                evaluate(raw, stage, rc)


if __name__ == "__main__":
    unittest.main()
