"""Independent synthetic transcript fixtures; no guest execution."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'build'))
from r800_gps_mock_xtra_transcript import review, MATRIX, MAX_LOG

HEAD = 'GpsInterface 0x1234abcd size 40\nCAPS 1234\ninit 0\ninject_time 1700000000000 ref 100 unc 500 -> 0\n'
TAIL = ('set_position_mode 0\nSTATUS 1\nFIX flags=1f lat=12.5000000 lon=-34.2500000 '
        'alt=100.0 spd=1.50 brg=90.0 acc=5.0 t=1700000000000\n'
        'NMEA $GPGGA,MOCK*00\nstart 0 (running 0 s)\nSTATUS 2\nstop 0\nCAPS 4321\n')
XTRA = ('', 'CAPS a101\nCAPS a102\nCAPS a103\nlto: injected 4 bytes -> 0\n',
        'CAPS a101\nCAPS a102\nlto: XTRA unavailable or init failed (3, -12)\n',
        'CAPS a101\nCAPS a102\nCAPS a103\nlto: injected 4 bytes -> -13\n',
        'CAPS a101\nlto: XTRA unavailable or init failed (2, 0)\n',
        'lto: missing, unsafe, oversized or changed file\n')


def log(case):
    return (HEAD+XTRA[case]+TAIL).encode()


class XtraTranscriptTests(unittest.TestCase):
    def test_exact_matrix(self):
        self.assertEqual(len(MATRIX), 11)
        for abi, case in MATRIX:
            with self.subTest(abi=abi, case=case):
                result = review(log(case), abi, case, 0)
                self.assertEqual(result['status'], 'MOCK_XTRA_TRANSCRIPT_MATCH')
                self.assertFalse(result['vendor_abi_verified'])
                self.assertFalse(result['safe_to_flash'])

    def test_disabled_has_no_lookup(self):
        self.assertIn('TRANSCRIPT_MISMATCH', review(log(1), 0, 0, 0)['problems'])

    def test_missing_data_has_no_lookup(self):
        for abi in (1, 2):
            self.assertIn('TRANSCRIPT_MISMATCH', review(log(1), abi, 5, 0)['problems'])

    def test_failed_init_never_injects(self):
        raw = log(2).replace(b'set_position_mode', b'CAPS a103\nset_position_mode')
        self.assertIn('TRANSCRIPT_MISMATCH', review(raw, 1, 2, 0)['problems'])

    def test_wrong_payload_and_order(self):
        for raw in (log(1).replace(b'CAPS a103', b'CAPS a1ff'),
                    log(1).replace(b'CAPS a101\nCAPS a102', b'CAPS a102\nCAPS a101'),
                    log(1).replace(b'injected 4 bytes', b'injected 3 bytes')):
            self.assertIn('TRANSCRIPT_MISMATCH', review(raw, 2, 1, 0)['problems'])

    def test_nonzero_exit_and_truncated(self):
        self.assertIn('GPS_LIFECYCLE_FAILED', review(log(1), 1, 1, 124)['problems'])
        self.assertIn('TRANSCRIPT_MISMATCH', review(log(1)[:-10], 1, 1, 0)['problems'])

    def test_invalid_inputs(self):
        for raw, abi, case, rc in ((b'', 0, 1, 0), (b'', True, 1, 0),
                                   (b'', 2, 0, 0), (b'x'*(MAX_LOG+1), 2, 1, 0),
                                   (b'\xff', 1, 1, 0), (b'', 1, 1, True)):
            with self.assertRaises(ValueError):
                review(raw, abi, case, rc)


if __name__ == '__main__':
    unittest.main()
