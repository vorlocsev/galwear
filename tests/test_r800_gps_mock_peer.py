"""Exercise the acceptance client against a scripted local UNIX socket, not GPS Bridge."""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import socket
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "build"))
from r800_gps_mock_peer import Peer, START, exercise, wait_log, LIMIT


class PeerTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.log = self.root / "daemon.log"

    def pair(self):
        a, b = socket.socketpair()
        self.addCleanup(a.close)
        self.addCleanup(b.close)
        a.settimeout(1)
        peer = Peer.__new__(Peer)
        peer.sock, peer.pending = a, b""
        return peer, b

    def test_fragmented_and_coalesced_replies(self):
        p, b = self.pair()
        b.sendall(b"STA")
        b.sendall(b"TUS 1\nSTATUS 2\n")
        p.expect(b"STATUS 1", b"STATUS 2")
        p.silent()

    def test_wrong_frame(self):
        p, b = self.pair()
        b.sendall(b"STATUS 99\n")
        with self.assertRaisesRegex(ValueError, "Unexpected socket frame"):
            p.expect(b"STATUS 1")

    def test_unexpected_eof_and_extra_data(self):
        p, b = self.pair()
        b.close()
        with self.assertRaisesRegex(ValueError, "Unexpected socket EOF"):
            p.expect(b"STATUS 1")
        p, b = self.pair()
        b.sendall(b"EXTRA\n")
        with self.assertRaisesRegex(ValueError, "Expected disconnect"):
            p.eof()

    def test_oversized_and_premature_reply(self):
        p, b = self.pair()
        b.sendall(b"x"*1025)
        with self.assertRaisesRegex(ValueError, "Oversized socket frame"):
            p.expect(b"STATUS 1")
        p, b = self.pair()
        b.sendall(b"STATUS 1\n")
        with self.assertRaisesRegex(ValueError, "before complete command"):
            p.silent()

    def test_log_bounds_and_timeout(self):
        self.log.write_bytes(b"not ready\n")
        with self.assertRaisesRegex(ValueError, "Missing daemon marker"):
            wait_log(self.log, b"ready", timeout=0)
        self.log.write_bytes(b"x"*(LIMIT+1))
        with self.assertRaisesRegex(ValueError, "Oversized daemon log"):
            wait_log(self.log, b"ready", timeout=0)

    def test_full_scripted_peer(self):
        path = self.root / "gps.sock"
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
            server.bind(str(path))
            server.listen(1)
            server.settimeout(6)
            self.log.write_bytes(b"listening on /opt/usr/r800dev/gps.sock\n")

            def append(raw):
                with self.log.open("ab") as stream:
                    stream.write(raw)

            def receive(conn, expected):
                raw = b""
                while len(raw) < len(expected):
                    chunk = conn.recv(len(expected)-len(raw))
                    if not chunk:
                        raise AssertionError("Unexpected client EOF")
                    raw += chunk
                self.assertEqual(raw, expected)

            def send(conn, *frames):
                conn.sendall(b"\n".join(frames)+b"\n")

            def serve():
                for stage in range(5):
                    conn, _ = server.accept()
                    with conn:
                        conn.settimeout(6)
                        if stage == 0:
                            receive(conn, b"START\nSTART\nTIME 1700000000123\nLOC 12.5 -34.25 25\n")
                            send(conn, *START)
                            append(b"inject_time 1700000000123 ref 100 unc 1000 -> 0\ninject_location (android) acc 25 -> 0\n")
                            receive(conn, b"STOP\nSTOP\nSTART\n")
                            send(conn, b"STATUS 2", *START)
                            self.assertEqual(conn.recv(1), b"")
                        elif stage == 1:
                            receive(conn, b"START\n")
                            send(conn, *START)
                            receive(conn, b"\0")
                        elif stage == 2:
                            receive(conn, b"X"*511)
                        elif stage == 3:
                            receive(conn, b"LOC 91 0 25\n")
                        else:
                            receive(conn, b"START\nSTOP\n")
                            send(conn, *START, b"STATUS 2")
                            self.assertEqual(conn.recv(1), b"")
                    append(b"client gone\n")

            with ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(serve)
                report = exercise(path, self.log)
                future.result(timeout=8)
        self.assertEqual(report["connections"], 5)
        self.assertFalse(report["vendor_abi_verified"])
        self.assertFalse(report["safe_to_flash"])


if __name__ == "__main__":
    unittest.main()
