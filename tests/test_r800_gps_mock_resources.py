"""Real host process and synthetic sample review tests; no QEMU."""
from pathlib import Path
import os
import signal
import tempfile
import subprocess
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'build'))
from r800_gps_mock_resources import identity, locate, sample, review, RSS_BUDGET_KIB
from r800_gps_mock_recovery import drive, CYCLES


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

    def test_recovery_drive_samples_real_process_behind_launcher(self):
        # A scripted peer stands in for QEMU, not for the proprietary HAL.
        code = r"""
import socket, sys, time
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from r800_gps_mock_peer import START
with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
    server.bind(sys.argv[2]); server.listen(1)
    log = Path(sys.argv[3])
    log.write_bytes(b'listening on /opt/usr/r800dev/gps.sock\n')
    def receive(conn, expected):
        raw = b''
        while len(raw) < len(expected):
            chunk = conn.recv(len(expected)-len(raw))
            if not chunk: raise RuntimeError('premature EOF')
            raw += chunk
        if raw != expected: raise RuntimeError('wrong command')
    for _ in range(int(sys.argv[4])):
        conn, _ = server.accept()
        with conn:
            receive(conn, b'START\n')
            conn.sendall(b'\n'.join(START)+b'\n')
            receive(conn, b'STOP\n')
            conn.sendall(b'STATUS 2\n')
            if conn.recv(1) != b'': raise RuntimeError('expected EOF')
        with log.open('ab') as stream: stream.write(b'client gone\n')
    time.sleep(30)
"""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            launcher = subprocess.Popen(['/bin/sh', '-c', '"$@" & wait', 'launcher', sys.executable,
                                         '-c', code, str(Path(__file__).resolve().parents[1] / 'build'),
                                         str(root/'gps.sock'), str(root/'daemon.log'), str(CYCLES)],
                                        start_new_session=True)
            try:
                report = drive(root/'gps.sock', root/'daemon.log', 5,
                               launcher_pid=launcher.pid, qemu=Path(sys.executable))
                self.assertEqual(report['status'], 'RESOURCE_COUNTS_STABLE')
                self.assertEqual(len(report['samples']), CYCLES)
                self.assertFalse(report['fd_leak_verified'])
            finally:
                os.killpg(launcher.pid, signal.SIGTERM)
                launcher.wait(timeout=3)

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
