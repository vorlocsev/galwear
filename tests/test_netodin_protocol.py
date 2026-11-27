"""Deterministic protocol simulations. No Wi-Fi socket or hardware is used."""
from __future__ import annotations

import io
from pathlib import Path
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
from test_installer_guard import fake_pit, synthetic_archive


class SimulatedWatch:
    """A minimal byte-stream mock, NOT a faithful SM-R800 protocol emulator."""

    def __init__(self, pit_data=None, bad_phase=None, no_pit=False):
        self.pit = fake_pit() if pit_data is None else pit_data
        self.bad_phase = bad_phase
        self.no_pit = no_pit
        self.response = bytearray()
        self.pit_offset = 0
        self.transfer_commands = []
        self.raw_blocks = 0
        self.reboot_commands = 0
        self.closed = False

    def sendall(self, payload):
        if payload == b"ODIN":
            self.response.extend(b"LOKE")
            return
        if len(payload) == 1024:
            cmd, sub = struct.unpack_from("<II", payload)
            if cmd == netodin.CMD_SETUP:
                result = (cmd, (3 << 16) if sub == 0 else 0)
            elif cmd == netodin.CMD_PIT:
                if sub == 1:
                    result = (cmd, 0 if self.no_pit else len(self.pit))
                elif sub == 2:
                    idx = struct.unpack_from("<I", payload, 8)[0]
                    if idx * 500 != self.pit_offset:
                        raise AssertionError("Unexpected PIT request sequence")
                    chunk = self.pit[self.pit_offset:self.pit_offset + 500]
                    self.pit_offset += len(chunk)
                    self.response.extend(chunk)
                    return
                else:
                    result = (cmd, 0)
            elif cmd == netodin.CMD_FILE_TRANSFER:
                self.transfer_commands.append(sub)
                result = (cmd, 1 if self.bad_phase == ("transfer", sub) else 0)
            elif cmd == netodin.CMD_SESSION_END:
                if sub == 1:
                    self.reboot_commands += 1
                result = (cmd, 0)
            else:
                raise AssertionError(f"Unexpected command {cmd}")
            self.response.extend(struct.pack("<II", *result))
            return
        if len(payload) == netodin.CHUNK_SIZE:
            self.raw_blocks += 1
            self.response.extend(struct.pack(
                "<II", 0, 1 if self.bad_phase == "chunk" else 0))
        else:
            raise AssertionError(f"Unexpected transfer size {len(payload)}")

    def recv(self, length):
        actual = self.response[:length]
        del self.response[:length]
        return bytes(actual)

    def settimeout(self, timeout):
        self.timeout = timeout

    def setsockopt(self, *args):
        pass

    def close(self):
        self.closed = True


class SimulatedServer:
    def __init__(self, watch):
        self.watch = watch
        self.closed = False

    def setsockopt(self, *args):
        pass

    def bind(self, address):
        pass

    def listen(self, count):
        pass

    def settimeout(self, timeout):
        pass

    def accept(self):
        return self.watch, ("192.168.49.20", 13579)

    def close(self):
        self.closed = True


class ReadAndAckTests(unittest.TestCase):
    def test_read_image_chunk_exact(self):
        self.assertEqual(netodin.read_image_chunk(io.BytesIO(b"abcd"), 4, "boot"), b"abcd")

    def test_read_image_chunk_short(self):
        with self.assertRaisesRegex(IOError, "Short image read"):
            netodin.read_image_chunk(io.BytesIO(b"ab"), 4, "boot")

    def test_read_image_chunk_empty(self):
        with self.assertRaisesRegex(IOError, "Short image read"):
            netodin.read_image_chunk(io.BytesIO(b""), 4, "boot")

    def test_read_image_chunk_none(self):
        with self.assertRaisesRegex(IOError, "Short image read"):
            netodin.read_image_chunk(mock.Mock(read=mock.Mock(return_value=None)), 4, "boot")

    def test_nonpositive_read_size_is_rejected(self):
        with self.assertRaises(ValueError):
            netodin.read_image_chunk(io.BytesIO(b"abcd"), 0, "boot")

    def test_transfer_ack_zero(self):
        netodin.require_transfer_success(0, "commit")

    def test_transfer_ack_nonzero_unsigned_error(self):
        for status in (1, 2, 0x7FFFFFFF, 0x80000001, 0xFFFFFFFF):
            with self.subTest(status=status):
                with self.assertRaises(IOError):
                    netodin.require_transfer_success(status, "commit")

    def test_recv_exact_aborts_on_disconnect(self):
        class BrokenSocket:
            def recv(self, n):
                return b""
        with self.assertRaises(ConnectionResetError):
            netodin.recv_exact(BrokenSocket(), 8)


class PrewriteProtocolTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.package = Path(self.tmp.name) / "R800-WearOS.tar.md5"
        synthetic_archive(self.package)

    def simulate(self, watch):
        server = SimulatedServer(watch)
        with mock.patch.object(netodin.socket, "socket", return_value=server):
            with mock.patch.object(netodin, "format_progress"):
                netodin.flash_ap_package(str(self.package), auto_reboot=False)
        return watch

    def test_good_synthetic_pit_can_reach_data_phase(self):
        watch = self.simulate(SimulatedWatch())
        self.assertEqual(watch.transfer_commands.count(3), len(r800_safety.EXPECTED_IMAGES))
        self.assertEqual(watch.raw_blocks, len(r800_safety.EXPECTED_IMAGES))
        self.assertEqual(watch.reboot_commands, 0)
        self.assertTrue(watch.closed)

    def test_bad_magic_never_starts_data_phase(self):
        watch = SimulatedWatch(pit_data=fake_pit(corrupt_magic=True))
        with self.assertRaises(r800_safety.SafetyError):
            self.simulate(watch)
        self.assertEqual(watch.transfer_commands, [])
        self.assertEqual(watch.raw_blocks, 0)

    def test_truncated_pit_never_starts_data_phase(self):
        watch = SimulatedWatch(pit_data=fake_pit()[:-1])
        with self.assertRaises(r800_safety.SafetyError):
            self.simulate(watch)
        self.assertEqual(watch.transfer_commands, [])

    def test_wrong_partition_mapping_never_starts_data_phase(self):
        watch = SimulatedWatch(pit_data=fake_pit(overrides={"dzImage": 99}))
        with self.assertRaises(r800_safety.SafetyError):
            self.simulate(watch)
        self.assertEqual(watch.transfer_commands, [])

    def test_missing_pit_never_starts_data_phase(self):
        watch = SimulatedWatch(no_pit=True)
        with self.assertRaises(r800_safety.SafetyError):
            self.simulate(watch)
        self.assertEqual(watch.transfer_commands, [])

    def test_invalid_geometry_never_starts_any_image(self):
        # Corrupt the last synthetic entry, proving that ALL entries are
        # validated before the first transfer, even if preceding entries fit.
        names = list(r800_safety.EXPECTED_IMAGES)
        begin = r800_safety.PIT_HEADER_SIZE + (len(names) - 1) * r800_safety.PIT_ENTRY_SIZE
        cases = (
            ("zero count", 24, 0, "Missing/zero PIT block count"),
            ("unknown device", 4, 4, "Unknown PIT device type"),
            ("range overflow", 20, 0xffffffff, "PIT block range overflow"),
            ("padded overflow", 24, 1, "exceeds assumed PIT partition capacity"),
        )
        for name, offset, value, diagnostic in cases:
            with self.subTest(case=name):
                pit = bytearray(fake_pit())
                struct.pack_into("<I", pit, begin + offset, value)
                watch = SimulatedWatch(pit_data=bytes(pit))
                with self.assertRaisesRegex(r800_safety.SafetyError, diagnostic):
                    self.simulate(watch)
                self.assertEqual(watch.transfer_commands, [])
                self.assertEqual(watch.raw_blocks, 0)
                self.assertEqual(watch.reboot_commands, 0)

    def test_window_start_nonzero_ack_stops_without_data(self):
        watch = SimulatedWatch(bad_phase=("transfer", 0))
        with self.assertRaises(IOError):
            self.simulate(watch)
        self.assertEqual(watch.raw_blocks, 0)
        self.assertEqual(watch.transfer_commands, [0])

    def test_window_size_nonzero_ack_stops_without_data(self):
        watch = SimulatedWatch(bad_phase=("transfer", 2))
        with self.assertRaises(IOError):
            self.simulate(watch)
        self.assertEqual(watch.raw_blocks, 0)
        self.assertEqual(watch.transfer_commands, [0, 2])

    def test_chunk_nonzero_ack_stops_without_commit(self):
        watch = SimulatedWatch(bad_phase="chunk")
        with self.assertRaises(IOError):
            self.simulate(watch)
        self.assertEqual(watch.transfer_commands, [0, 2])
        self.assertEqual(watch.raw_blocks, 1)

    def test_commit_nonzero_ack_stops_without_next_image(self):
        watch = SimulatedWatch(bad_phase=("transfer", 3))
        with self.assertRaises(IOError):
            self.simulate(watch)
        self.assertEqual(watch.transfer_commands, [0, 2, 3])
        self.assertEqual(watch.raw_blocks, 1)


if __name__ == "__main__":
    unittest.main()
