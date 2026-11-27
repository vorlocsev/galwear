"""Synthetic log review tests, not GPS Bridge execution."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'build'))
from r800_gps_mock_recovery import review, expected, STAGES, CYCLES, LIMIT


class RecoveryTests(unittest.TestCase):
    def raw(self, stage):
        return ('\n'.join(expected(stage)) + '\n').encode()

    def test_all_stages(self):
        for stage in STAGES:
            result = review(self.raw(stage), stage, 0 if stage == 5 else 1)
            self.assertEqual(result['connections'], CYCLES if stage == 5 else 1)
            self.assertFalse(result['safe_to_flash'])
            self.assertFalse(result['fd_leak_verified'])

    def test_second_retry_rejected(self):
        raw = self.raw(3) + b'start failed, re-init\n'
        with self.assertRaisesRegex(ValueError, 'lifecycle'):
            review(raw, 3, 1)

    def test_failed_reinit_no_second_cleanup(self):
        with self.assertRaisesRegex(ValueError, 'lifecycle'):
            review(self.raw(6) + b'CAPS 4321\n', 6, 1)

    def test_stop_failure_no_new_client(self):
        with self.assertRaisesRegex(ValueError, 'lifecycle'):
            review(self.raw(4) + b'client connected\n', 4, 1)

    def test_missing_reconnect(self):
        raw = self.raw(5).replace(b'client gone\n', b'', 1)
        with self.assertRaisesRegex(ValueError, 'lifecycle'):
            review(raw, 5, 0)

    def test_wrong_exit_and_timeout(self):
        for rc in (0, 124, 137, True):
            with self.assertRaisesRegex(ValueError, 'exit status'):
                review(self.raw(3), 3, rc)

    def test_unexpected_diagnostics(self):
        for line in (b'CAPS dead\n', b'session start -> -99\n', b'loader error\n'):
            with self.assertRaisesRegex(ValueError, 'lifecycle'):
                review(self.raw(5) + line, 5, 0)

    def test_bounds_and_types(self):
        for raw, stage in ((b'x'*(LIMIT+1), 5), (b'', 1), (b'', True)):
            with self.assertRaises(ValueError):
                review(raw, stage, 0)


if __name__ == '__main__':
    unittest.main()
