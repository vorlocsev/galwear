#!/usr/bin/env python3
"""Host-only real bridge + Android HAL tests with a synthetic libbrcm."""
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]


class BridgeIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix="r800-gps-both-")
        cls.addClassCleanup(cls.tmp.cleanup)
        cls.bin = Path(cls.tmp.name)
        flags = ["cc", "-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror",
                 "-UNDEBUG", "-pthread", "-fsanitize=undefined", "-fno-sanitize-recover=all"]
        for name, args in (
            ("gpsbridge", ["-DR800_GPS_BRIDGE_HOST_TEST", "src/tools/gps/gpsbridge.c", "-ldl"]),
            ("libbrcm-test.so", ["-fPIC", "-shared", "tests/r800_mock_brcm.c"]),
            ("android-peer", ["tests/test_r800_gps_both_sides.c"]),
        ):
            subprocess.run(flags + args + ["-o", str(cls.bin/name)],
                           cwd=ROOT, check=True, timeout=30)

    def launch(self, mode):
        tmp = tempfile.TemporaryDirectory(prefix="r800-bridge-")
        self.addCleanup(tmp.cleanup)
        cwd = Path(tmp.name)
        shutil.copy2(self.bin/"libbrcm-test.so", cwd/"libbrcm-test.so")
        log = cwd/"bridge.log"
        stream = log.open("wb")
        self.addCleanup(stream.close)
        proc = subprocess.Popen([str(self.bin/"gpsbridge"), "daemon"], cwd=cwd,
                                env=dict(os.environ,R800_MOCK_MODE=mode),
                                stdout=stream, stderr=subprocess.STDOUT)
        def stop():
            if proc.poll() is None:
                proc.terminate()
                try: proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill(); proc.wait(timeout=3)
        self.addCleanup(stop)
        for _ in range(500):
            if (cwd/"gps.sock").exists() and "listening on ./gps.sock\n" in log.read_text(): break
            if proc.poll() is not None: self.fail(log.read_text())
            time.sleep(.01)
        else: self.fail("bridge socket not ready")
        return cwd, proc, log

    def test_both_real_sources(self):
        cwd, proc, log = self.launch("normal")
        run = subprocess.run([str(self.bin/"android-peer")], cwd=cwd,
                             capture_output=True,text=True,timeout=25)
        self.assertEqual(run.returncode,0,run.stdout+run.stderr+log.read_text())
        self.assertIn("GPS_BOTH_SIDES=PASS",run.stdout)
        evidence=log.read_text()
        self.assertEqual(evidence.count("MOCK_START\n"),2)
        self.assertEqual(evidence.count("MOCK_STOP\n"),2)
        self.assertIn("MOCK_LOC\n",evidence)
        self.assertIn("unc 50 -> 0",evidence)
        self.assertIsNone(proc.poll())

    def test_reinit_failure_closes_service(self):
        cwd,proc,log=self.launch("fail-reinit")
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as s:
            s.settimeout(5); s.connect(str(cwd/"gps.sock")); s.sendall(b"START\n")
            self.assertEqual(s.recv(1),b"")
        self.assertEqual(proc.wait(timeout=5),1)
        evidence=log.read_text()
        self.assertEqual(evidence.count("MOCK_INIT\n"),2)
        self.assertEqual(evidence.count("MOCK_START\n"),1)
        self.assertEqual(evidence.count("MOCK_CLEANUP\n"),1)

    def test_stop_failure_closes_service(self):
        cwd,proc,log=self.launch("fail-stop")
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as s:
            s.settimeout(5); s.connect(str(cwd/"gps.sock")); s.sendall(b"START\nSTOP\n")
            while s.recv(4096): pass
        self.assertEqual(proc.wait(timeout=5),1)
        self.assertEqual(log.read_text().count("MOCK_STOP\n"),1)


if __name__ == "__main__":
    unittest.main()
