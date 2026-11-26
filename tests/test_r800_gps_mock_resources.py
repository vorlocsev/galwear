"""Real host process and synthetic sample review tests; no QEMU."""
from pathlib import Path
import subprocess
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'build'))
from r800_gps_mock_resources import identity, locate, sample, review, RSS_BUDGET_KIB


class ResourceTests(unittest.TestCase):
    def test_real_child_descriptor_thread_and_memory(self):
        code = "import sys,threading; f=open('/dev/null'); t=threading.Thread(target=threading.Event().wait,daemon=True); t.start(); print('ready',flush=True); sys.stdin.readline(); f.close(); print('closed',flush=True); sys.stdin.readline()"
        with subprocess.Popen([sys.executable, '-c', code], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True) as p:
            try:
                self.assertEqual(p.stdout.readline().strip(), 'ready')
                target = locate(p.pid, sys.executable)
                self.assertEqual(target[0], p.pid)
                before = sample(target)
                self.assertGreaterEqual(before['threads'], 2)
                self.assertGreater(before['rss_kib'], 0)
                p.stdin.write('\n'); p.stdin.flush()
                self.assertEqual(p.stdout.readline().strip(), 'closed')
                after = sample(target)
                self.assertEqual(after['fds'], before['fds']-1)
                self.assertEqual(after['threads'], before['threads'])
                with self.assertRaisesRegex(ValueError, 'identity changed'):
                    sample((p.pid, identity(p.pid)+1))
            finally:
                p.terminate()
                p.wait(timeout=3)

    def series(self):
        return [{'fds': 5, 'threads': 2, 'rss_kib': 10000} for _ in range(8)]

    def test_stable_and_warmup(self):
        values = self.series()
        values[0]['fds'] = 7
        values[-1]['rss_kib'] += RSS_BUDGET_KIB
        result = review(values, 8)
        self.assertEqual(result['status'], 'RESOURCE_COUNTS_STABLE')
        self.assertFalse(result['memory_leak_verified'])
        self.assertFalse(result['safe_to_flash'])

    def test_fd_growth_and_thread_growth(self):
        values = self.series()
        values[3]['fds'] += 1
        values[5]['threads'] += 1
        self.assertEqual(review(values, 8)['problems'], ['fds_count_changed', 'threads_count_changed'])

    def test_rss_peak_not_just_final(self):
        values = self.series()
        values[4]['rss_kib'] += RSS_BUDGET_KIB + 1
        self.assertIn('rss_budget_exceeded', review(values, 8)['problems'])

    def test_incomplete_and_bad_samples(self):
        with self.assertRaises(ValueError):
            review(self.series()[:-1], 8)
        values = self.series()
        values[3]['fds'] = True
        with self.assertRaises(ValueError):
            review(values, 8)

    def test_wrong_executable(self):
        with self.assertRaisesRegex(ValueError, 'exactly one'):
            locate(__import__('os').getpid(), '/bin/false')


if __name__ == '__main__':
    unittest.main()
