"""Stage 9: offline Odin/PIT fault injection. No device or network traffic.

The mocked peer is NOT an accurate Samsung bootloader. These tests prove that
unexpected responses stop a *software simulation*, not that PIT framing is
correct for SM-R800 hardware.
"""
from __future__ import annotations

from pathlib import Path
import socket
import struct
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "installer"))
sys.path.insert(0, str(ROOT / "tests"))

import netodin
import r800_safety
from test_recovery_audit import build_archives
from test_installer_guard import fake_pit
from test_netodin_protocol import SimulatedWatch, SimulatedServer


class OneByteSocket:
    def __init__(self, payload):
        self.remaining = bytearray(payload)

    def recv(self, length):
        chunk = bytes(self.remaining[:min(length, 1)])
        del self.remaining[:len(chunk)]
        return chunk


class PITWireFaults(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.package, self.reference = build_archives(Path(self.tmp.name))

    def run_mock(self, peer, server=None):
        server = server or SimulatedServer(peer)
        with mock.patch.object(netodin.socket, "socket", return_value=server):
            with mock.patch.object(netodin, "format_progress"):
                netodin.flash_ap_package(
                    str(self.package),
                    combination_path=str(self.reference),
                    auto_reboot=False)
        return peer

    def assert_no_data_commands(self, peer):
        self.assertEqual(peer.transfer_commands, [])
        self.assertEqual(peer.raw_blocks, 0)

    def test_fragmented_recv_exact_reassembles_bytes(self):
        self.assertEqual(netodin.recv_exact(OneByteSocket(b"LOKE"), 4), b"LOKE")

    def test_truncated_ack_aborts(self):
        sock = OneByteSocket(struct.pack("<I", netodin.CMD_SETUP))
        with self.assertRaises(ConnectionResetError):
            netodin.send_control_packet(
                sock=type("SendSocket", (), {
                    "sendall": lambda self, data: None,
                    "recv": sock.recv,
                })(),
                cmd=netodin.CMD_SETUP, sub=0)

    def test_valid_synthetic_pit_can_be_downloaded(self):
        peer = SimulatedWatch()
        result = netodin.receive_live_pit(peer)
        self.assertEqual(result, fake_pit())

    def test_short_pit_announcement_refused(self):
        peer = SimulatedWatch(pit_data=b"short")
        with self.assertRaisesRegex(r800_safety.SafetyError, "PIT wire length"):
            self.run_mock(peer)
        self.assert_no_data_commands(peer)

    def test_oversize_pit_announcement_refused(self):
        peer = SimulatedWatch(
            pit_data=b"X" * (netodin.MAX_WIRE_PIT_SIZE + 1))
        with self.assertRaisesRegex(r800_safety.SafetyError, "PIT wire length"):
            self.run_mock(peer)
        self.assert_no_data_commands(peer)

    def test_pit_transfer_disconnect_refused(self):
        class DisconnectingPeer(SimulatedWatch):
            def sendall(self, payload):
                if len(payload) == 1024:
                    cmd, sub = struct.unpack_from("<II", payload)
                    if cmd == netodin.CMD_PIT and sub == 2:
                        index = struct.unpack_from("<I", payload, 8)[0]
                        if index >= 1:
                            return  # No bytes received; recv() returns EOF.
                super().sendall(payload)
        peer = DisconnectingPeer()
        with self.assertRaises(ConnectionResetError):
            self.run_mock(peer)
        self.assert_no_data_commands(peer)

    def test_pit_transfer_timeout_refused(self):
        class TimeoutPeer(SimulatedWatch):
            def recv(self, length):
                if self.pit_offset > 500 and not self.response:
                    raise socket.timeout("synthetic interruption")
                return super().recv(length)
        peer = TimeoutPeer()
        with self.assertRaises(socket.timeout):
            self.run_mock(peer)
        self.assert_no_data_commands(peer)

    def test_pit_bad_finalize_ack_refused(self):
        class WrongAckPeer(SimulatedWatch):
            def sendall(self, payload):
                if len(payload) == 1024:
                    cmd, sub = struct.unpack_from("<II", payload)
                    if cmd == netodin.CMD_PIT and sub == 3:
                        self.response.extend(struct.pack("<II", netodin.CMD_SETUP, 0))
                        return
                super().sendall(payload)
        peer = WrongAckPeer()
        with self.assertRaisesRegex(OSError, "Unexpected Odin ACK"):
            self.run_mock(peer)
        self.assert_no_data_commands(peer)

    def test_pit_nonzero_finalize_status_refused(self):
        class StatusPeer(SimulatedWatch):
            def sendall(self, payload):
                if len(payload) == 1024:
                    cmd, sub = struct.unpack_from("<II", payload)
                    if cmd == netodin.CMD_PIT and sub == 3:
                        self.response.extend(struct.pack("<II", netodin.CMD_PIT, 1))
                        return
                super().sendall(payload)
        peer = StatusPeer()
        with self.assertRaisesRegex(r800_safety.SafetyError, "finalize"):
            self.run_mock(peer)
        self.assert_no_data_commands(peer)

    def test_unexpected_last_pit_chunk_padding_aborts(self):
        # A peer sending 500 bytes even for a shorter final chunk would
        # leave unconsumed padding. The current code must fail closed, not
        # mistake that padding for a valid finalize ACK.
        class PaddedLastPeer(SimulatedWatch):
            def sendall(self, payload):
                if len(payload) == 1024:
                    cmd, sub = struct.unpack_from("<II", payload)
                    if cmd == netodin.CMD_PIT and sub == 2:
                        idx = struct.unpack_from("<I", payload, 8)[0]
                        if idx == len(self.pit) // 500:
                            rem = len(self.pit) % 500
                            if rem:
                                super().sendall(payload)
                                self.response.extend(b"\x00" * (500 - rem))
                                return
                super().sendall(payload)
        peer = PaddedLastPeer()
        with self.assertRaisesRegex(OSError, "Unexpected Odin ACK"):
            self.run_mock(peer)
        self.assert_no_data_commands(peer)

    def test_setup_ack_command_mismatch_refused(self):
        class WrongSetupPeer(SimulatedWatch):
            def sendall(self, payload):
                if len(payload) == 1024:
                    cmd, sub = struct.unpack_from("<II", payload)
                    if cmd == netodin.CMD_SETUP and sub == 0:
                        self.response.extend(struct.pack("<II", 12345, 0))
                        return
                super().sendall(payload)
        peer = WrongSetupPeer()
        with self.assertRaisesRegex(OSError, "Unexpected Odin ACK"):
            self.run_mock(peer)
        self.assert_no_data_commands(peer)

    def test_bad_handshake_refused(self):
        class BadHandshakePeer(SimulatedWatch):
            def sendall(self, payload):
                if payload == b"ODIN":
                    self.response.extend(b"NOPE")
                else:
                    super().sendall(payload)
        peer = BadHandshakePeer()
        with self.assertRaisesRegex(ValueError, "Handshake failed"):
            self.run_mock(peer)
        self.assert_no_data_commands(peer)

    def test_connection_timeout_closes_listener(self):
        peer = SimulatedWatch()
        class TimedOutServer(SimulatedServer):
            def accept(self):
                raise socket.timeout("synthetic timeout")
        srv = TimedOutServer(peer)
        with self.assertRaises(TimeoutError):
            self.run_mock(peer, srv)
        self.assertTrue(srv.closed)
        self.assert_no_data_commands(peer)

    def test_other_accept_failure_closes_listener(self):
        peer = SimulatedWatch()
        class ErrorServer(SimulatedServer):
            def accept(self):
                raise OSError("synthetic networking failure")
        srv = ErrorServer(peer)
        with self.assertRaisesRegex(OSError, "synthetic networking"):
            self.run_mock(peer, srv)
        self.assertTrue(srv.closed)
        self.assert_no_data_commands(peer)


if __name__ == "__main__":
    unittest.main()
