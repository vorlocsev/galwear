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
            ("android-peer-v2", ["-DR800_GPS_IPC_V2=1", "tests/test_r800_gps_both_sides.c"]),
            ("android-peer-default", ["-DR800_GPS_TEST_SOURCE_DEFAULT=1", "tests/test_r800_gps_both_sides.c"]),
            ("android-peer-restart", ["tests/test_r800_gps_hal_bridge_restart.c"]),
        ):
            subprocess.run(flags + args + ["-o", str(cls.bin/name)],
                           cwd=ROOT, check=True, timeout=30)

    def launch(self, mode):
        tmp = tempfile.TemporaryDirectory(prefix="r800-bridge-")
        self.addCleanup(tmp.cleanup)
        cwd = Path(tmp.name)
        shutil.copy2(self.bin/"libbrcm-test.so", cwd/"libbrcm-test.so")
        proc, log = self.spawn_bridge(cwd, mode, "bridge.log")
        return cwd, proc, log

    def spawn_bridge(self, cwd, mode, filename):
        log = cwd/filename
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
        return proc, log

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

    def test_both_real_sources_v2_async(self):
        cwd,proc,log=self.launch("async-data")
        run=subprocess.run([str(self.bin/"android-peer-v2")],cwd=cwd,
                           capture_output=True,text=True,timeout=25)
        self.assertEqual(run.returncode,0,run.stdout+run.stderr+log.read_text())
        self.assertIn("GPS_BOTH_SIDES=PASS",run.stdout)
        evidence=log.read_text()
        self.assertEqual(evidence.count("MOCK_START\n"),2)
        self.assertEqual(evidence.count("MOCK_STOP\n"),2)
        self.assertEqual(evidence.count("MOCK_ASYNC_DATA\n"),2)
        self.assertIsNone(proc.poll())

    def test_default_build_uses_v2(self):
        cwd,proc,log=self.launch("async-data")
        run=subprocess.run([str(self.bin/"android-peer-default")],cwd=cwd,
                           capture_output=True,text=True,timeout=25)
        self.assertEqual(run.returncode,0,run.stdout+run.stderr+log.read_text())
        self.assertIn("GPS_BOTH_SIDES=PASS",run.stdout)
        self.assertEqual(log.read_text().count("MOCK_ASYNC_DATA\n"),2)
        self.assertIsNone(proc.poll())

    def restart_hal_case(self, mode, graceful):
        cwd, original, original_log = self.launch("async-data")
        client_log = cwd/"hal-restart.log"
        with client_log.open("wb") as output:
            hal = subprocess.Popen([str(self.bin/"android-peer-restart"), mode],
                                   cwd=cwd, stdin=subprocess.PIPE,
                                   stdout=output, stderr=subprocess.STDOUT)
            def wait_marker(marker):
                deadline = time.monotonic()+12
                while time.monotonic()<deadline:
                    if marker in client_log.read_text():
                        return
                    if hal.poll() is not None:
                        self.fail(client_log.read_text())
                    time.sleep(.01)
                self.fail("HAL marker missing: "+marker+"\n"+client_log.read_text())
            try:
                wait_marker("FIRST_SESSION_READY\n")
                deadline=time.monotonic()+5
                while "MOCK_ASYNC_DATA\n" not in original_log.read_text():
                    if original.poll() is not None or time.monotonic()>=deadline:
                        self.fail(original_log.read_text())
                    time.sleep(.01)
                if graceful:
                    original.terminate()
                    self.assertEqual(original.wait(timeout=5),0,original_log.read_text())
                    self.assertFalse((cwd/"gps.sock").exists())
                    self.assertFalse((cwd/"gps.sock.owner").exists())
                else:
                    original.kill()
                    self.assertLess(original.wait(timeout=5),0)
                    self.assertTrue((cwd/"gps.sock.owner").is_file())
                wait_marker("DISCONNECTED\n")
                replacement, log = self.spawn_bridge(cwd,"async-data","replacement.log")
                if mode=="idle":
                    wait_marker("IDLE_CONNECTION_READY\n")
                    self.assertNotIn("MOCK_START\n",log.read_text())
                    hal.stdin.write(b"\n")
                    hal.stdin.flush()
                self.assertEqual(hal.wait(timeout=15),0,client_log.read_text()+log.read_text())
                self.assertIn("GPS_HAL_BRIDGE_RESTART=PASS",client_log.read_text())
                evidence=log.read_text()
                self.assertEqual(evidence.count("MOCK_START\n"),1)
                self.assertEqual(evidence.count("MOCK_STOP\n"),1)
                self.assertEqual(evidence.count("MOCK_ASYNC_DATA\n"),1)
                self.assertIsNone(replacement.poll())
            finally:
                if hal.poll() is None:
                    hal.kill()
                    hal.wait(timeout=5)
                hal.stdin.close()

    def test_default_hal_recovers_after_bridge_sigkill(self):
        self.restart_hal_case("active",False)

    def test_default_hal_recovers_after_bridge_sigterm(self):
        self.restart_hal_case("active",True)

    def test_default_hal_stop_during_bridge_outage(self):
        self.restart_hal_case("idle",False)

    def test_v2_async_data_and_reconnect(self):
        cwd,proc,log=self.launch("async-data")
        for _ in range(2):
            with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as s:
                s.settimeout(5); s.connect(str(cwd/"gps.sock"))
                with s.makefile("rb") as lines:
                    s.sendall(b"HELLO 2\nSTART 1\n")
                    self.assertEqual(lines.readline(),b"READY 2\n")
                    self.assertEqual(lines.readline(),b"ACK START 1\n")
                    s.sendall(b"LOC 52 5 0.25\n")
                    self.assertTrue(lines.readline().startswith(b"DATA 1 FIX "))
                    self.assertTrue(lines.readline().startswith(b"DATA 1 NMEA "))
                    s.sendall(b"STOP 1\n")
                    self.assertEqual(lines.readline(),b"ACK STOP 1\n")
        self.assertEqual(log.read_text().count("MOCK_ASYNC_DATA\n"),2)
        self.assertIsNone(proc.poll())

    def test_existing_file_preserved(self):
        with tempfile.TemporaryDirectory(prefix="r800-gps-existing-") as temp:
            cwd=Path(temp)
            shutil.copy2(self.bin/"libbrcm-test.so",cwd/"libbrcm-test.so")
            marker=cwd/"gps.sock"
            marker.write_bytes(b"preserve")
            run=subprocess.run([str(self.bin/"gpsbridge"),"daemon"],cwd=cwd,
                               capture_output=True,timeout=5)
            self.assertEqual(run.returncode,1)
            self.assertEqual(marker.read_bytes(),b"preserve")

    def test_duplicate_and_crash_recovery(self):
        cwd,proc,log=self.launch("normal")
        old_inode=(cwd/"gps.sock").stat().st_ino
        run=subprocess.run([str(self.bin/"gpsbridge"),"daemon"],cwd=cwd,
                           capture_output=True,timeout=5)
        self.assertEqual(run.returncode,1)
        self.assertNotIn(b"MOCK_INIT",run.stdout)
        self.assertEqual((cwd/"gps.sock").stat().st_ino,old_inode)
        proc.kill()
        proc.wait(timeout=5)
        self.assertTrue((cwd/"gps.sock.owner").is_file())
        with (cwd/"restarted.log").open("wb") as out:
            again=subprocess.Popen([str(self.bin/"gpsbridge"),"daemon"],cwd=cwd,
                                   stdout=out,stderr=subprocess.STDOUT)
            try:
                for _ in range(500):
                    if b"listening on ./gps.sock\n" in (cwd/"restarted.log").read_bytes():
                        break
                    if again.poll() is not None:
                        self.fail((cwd/"restarted.log").read_text())
                    time.sleep(.01)
                else: self.fail("restart not ready")
                self.assertIsNone(again.poll())
                with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as peer:
                    peer.settimeout(5)
                    peer.connect(str(cwd/"gps.sock"))
                    peer.sendall(b"START\n")
                    self.assertTrue(peer.recv(4096))
            finally:
                again.kill()
                again.wait(timeout=5)

    def test_socket_mode(self):
        cwd,proc,log=self.launch("normal")
        self.assertEqual((cwd/"gps.sock").stat().st_mode & 0o777,0o660)

    def test_reinit_failure_closes_service(self):
        cwd,proc,log=self.launch("fail-reinit")
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as s:
            s.settimeout(5); s.connect(str(cwd/"gps.sock")); s.sendall(b"START\n")
            self.assertEqual(s.recv(1),b"")
        self.assertEqual(proc.wait(timeout=5),1)
        evidence=log.read_text()
        self.assertEqual(evidence.count("MOCK_INIT\n"),2)
        self.assertEqual(evidence.count("MOCK_START\n"),0)
        self.assertEqual(evidence.count("MOCK_CLEANUP\n"),1)

    def test_start_failure_never_reinitializes(self):
        cwd,proc,log=self.launch("fail-start")
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as s:
            s.settimeout(5); s.connect(str(cwd/"gps.sock")); s.sendall(b"START\n")
            self.assertEqual(s.recv(1),b"")
        self.assertEqual(proc.wait(timeout=5),1)
        evidence=log.read_text()
        self.assertEqual(evidence.count("MOCK_INIT\n"),1)
        self.assertEqual(evidence.count("MOCK_START\n"),1)
        self.assertNotIn("MOCK_CLEANUP\n",evidence)
        self.assertNotIn("MOCK_STOP\n",evidence)

    def test_late_data_dropped_during_stop_and_idle(self):
        cwd,proc,log=self.launch("late-data")
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as s:
            s.settimeout(5); s.connect(str(cwd/"gps.sock"))
            with s.makefile("rb") as lines:
                s.sendall(b"START\n")
                self.assertEqual(lines.readline(),b"STATUS 1\n")
                self.assertTrue(lines.readline().startswith(b"FIX "))
                self.assertTrue(lines.readline().startswith(b"NMEA "))
                s.sendall(b"STOP\n")
                self.assertEqual(lines.readline(),b"STATUS 2\n")
                s.sendall(b"TIME 123 0 100\nSTART\n")
                self.assertEqual(lines.readline(),b"STATUS 1\n")
                self.assertTrue(lines.readline().startswith(b"FIX "))
                self.assertTrue(lines.readline().startswith(b"NMEA "))
                s.sendall(b"STOP\n")
                self.assertEqual(lines.readline(),b"STATUS 2\n")
        self.assertIn("MOCK_LATE_DATA\n",log.read_text())
        self.assertFalse((cwd/"gps.last").exists())
        self.assertIsNone(proc.poll())

    def test_v2_ack_order_and_session_ids(self):
        cwd,proc,log=self.launch("normal")
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as s:
            s.settimeout(5); s.connect(str(cwd/"gps.sock"))
            with s.makefile("rb") as lines:
                s.sendall(b"HELLO 2\nSTART 1\n")
                self.assertEqual(lines.readline(),b"READY 2\n")
                self.assertEqual(lines.readline(),b"ACK START 1\n")
                s.sendall(b"TIME 123 0 100\nLOC 52 5 0.25\nSTOP 1\n")
                self.assertEqual(lines.readline(),b"ACK STOP 1\n")
                s.sendall(b"START 2\nSTOP 2\n")
                self.assertEqual(lines.readline(),b"ACK START 2\n")
                self.assertEqual(lines.readline(),b"ACK STOP 2\n")
                s.sendall(b"START 1\n")
                self.assertEqual(lines.readline(),b"")
        evidence=log.read_text()
        self.assertEqual(evidence.count("MOCK_START\n"),2)
        self.assertEqual(evidence.count("MOCK_STOP\n"),2)
        self.assertIn("MOCK_LOC\n",evidence)
        self.assertIsNone(proc.poll())

    def test_v2_no_implicit_downgrade(self):
        cwd,proc,log=self.launch("normal")
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as s:
            s.settimeout(5); s.connect(str(cwd/"gps.sock"))
            with s.makefile("rb") as lines:
                s.sendall(b"HELLO 2\nSTART\n")
                self.assertEqual(lines.readline(),b"READY 2\n")
                self.assertEqual(lines.readline(),b"")
        self.assertNotIn("MOCK_START\n",log.read_text())
        self.assertIsNone(proc.poll())

    def test_sigterm_idle_cleans_up(self):
        cwd,proc,log=self.launch("normal")
        proc.terminate()
        self.assertEqual(proc.wait(timeout=5),0,log.read_text())
        evidence=log.read_text()
        self.assertEqual(evidence.count("MOCK_CLEANUP\n"),1)
        self.assertNotIn("MOCK_STOP\n",evidence)
        self.assertFalse((cwd/"gps.sock").exists())
        self.assertFalse((cwd/"gps.sock.owner").exists())

    def test_sigterm_active_stops_and_cleans_up(self):
        cwd,proc,log=self.launch("normal")
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as s:
            s.settimeout(5); s.connect(str(cwd/"gps.sock")); s.sendall(b"START\n")
            for _ in range(500):
                if "session start -> 0\n" in log.read_text(): break
                if proc.poll() is not None: self.fail(log.read_text())
                time.sleep(.01)
            else: self.fail("active session not confirmed")
            proc.terminate()
            self.assertEqual(proc.wait(timeout=5),0,log.read_text())
        evidence=log.read_text()
        self.assertEqual(evidence.count("MOCK_STOP\n"),1)
        self.assertEqual(evidence.count("MOCK_CLEANUP\n"),1)
        self.assertLess(evidence.index("MOCK_STOP\n"),evidence.index("MOCK_CLEANUP\n"))
        self.assertFalse((cwd/"gps.sock").exists())
        self.assertFalse((cwd/"gps.sock.owner").exists())

    def test_stop_failure_closes_service(self):
        cwd,proc,log=self.launch("fail-stop")
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as s:
            s.settimeout(5); s.connect(str(cwd/"gps.sock")); s.sendall(b"START\nSTOP\n")
            while s.recv(4096): pass
        self.assertEqual(proc.wait(timeout=5),1)
        self.assertEqual(log.read_text().count("MOCK_STOP\n"),1)


if __name__ == "__main__":
    unittest.main()
