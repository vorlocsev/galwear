"""Synthetic-only PIT geometry and prewrite transfer-size checks."""
from __future__ import annotations

from pathlib import Path
import struct
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "installer"))
sys.path.insert(0, str(ROOT / "tests"))

import netodin
import r800_geometry as geo
from r800_safety import EXPECTED_IMAGES, SafetyError
from test_installer_guard import fake_pit
from test_recovery_audit import build_archives
from test_netodin_protocol import SimulatedWatch, SimulatedServer


def replace_pit_field(pit: bytes, filename: str, offset: int, value: int) -> bytes:
    result = bytearray(pit)
    count = struct.unpack_from("<I", result, 4)[0]
    for i in range(count):
        begin = 28 + 132 * i
        name = result[begin + 68:begin + 100].split(b"\0", 1)[0].decode()
        if name == filename:
            struct.pack_into("<I", result, begin + offset, value)
            return bytes(result)
    raise ValueError("fixture image not found")


def simple_members(sizes=None):
    sizes = sizes or {}
    return [SimpleNamespace(name=n, size=sizes.get(n, 1))
            for n in EXPECTED_IMAGES]


class GeometryTests(unittest.TestCase):
    def test_synthetic_pit_geometry_is_read(self):
        geometry = geo.parse_pit_geometry(fake_pit())
        self.assertEqual(set(geometry), set(EXPECTED_IMAGES))
        self.assertEqual(geometry["dzImage"].capacity_bytes, 8 * 1024 * 1024)

    def test_synthetic_flash_plan_is_complete(self):
        g = geo.parse_pit_geometry(fake_pit())
        plan = geo.plan_image_transfers(g, simple_members())
        self.assertEqual(len(plan), 12)
        self.assertTrue(all(p["transmitted_padded_bytes"] == 131072 for p in plan))

    def test_zero_blocks_refused(self):
        data = replace_pit_field(fake_pit(), "dzImage", 24, 0)
        with self.assertRaisesRegex(SafetyError, "zero PIT block"):
            geo.parse_pit_geometry(data)

    def test_unknown_device_type_refused(self):
        data = replace_pit_field(fake_pit(), "dzImage", 4, 99)
        with self.assertRaisesRegex(SafetyError, "device type"):
            geo.parse_pit_geometry(data)

    def test_overflowing_range_refused(self):
        data = replace_pit_field(fake_pit(), "dzImage", 20, 0xFFFFFFFF)
        with self.assertRaisesRegex(SafetyError, "range overflow"):
            geo.parse_pit_geometry(data)

    def test_image_equal_to_capacity_fits(self):
        g = geo.parse_pit_geometry(fake_pit())
        plan = geo.plan_image_transfers(g, simple_members({"user.img": 8 * 1024 * 1024}))
        user = next(p for p in plan if p["image"] == "user.img")
        self.assertEqual(user["image_bytes"], user["assumed_partition_bytes"])

    def test_image_over_capacity_refused(self):
        g = geo.parse_pit_geometry(fake_pit())
        with self.assertRaisesRegex(SafetyError, "user.img exceeds"):
            geo.plan_image_transfers(g, simple_members({"user.img": 8 * 1024 * 1024 + 1}))

    def test_padded_image_over_capacity_refused(self):
        data = replace_pit_field(fake_pit(), "dzImage", 24, 200)  # 102400 bytes
        g = geo.parse_pit_geometry(data)
        with self.assertRaisesRegex(SafetyError, "padded=131072"):
            geo.plan_image_transfers(g, simple_members())

    def test_missing_member_refused(self):
        g = geo.parse_pit_geometry(fake_pit())
        with self.assertRaisesRegex(SafetyError, "missing archive members"):
            geo.plan_image_transfers(g, simple_members()[1:])

    def test_duplicate_member_refused(self):
        g = geo.parse_pit_geometry(fake_pit())
        with self.assertRaisesRegex(SafetyError, "duplicate firmware"):
            geo.plan_image_transfers(g, simple_members() + [simple_members()[0]])

    def test_unknown_member_refused(self):
        g = geo.parse_pit_geometry(fake_pit())
        with self.assertRaisesRegex(SafetyError, "Unexpected"):
            geo.plan_image_transfers(g, simple_members() + [SimpleNamespace(name="cm.bin", size=1)])

    def test_zero_size_refused(self):
        g = geo.parse_pit_geometry(fake_pit())
        with self.assertRaisesRegex(SafetyError, "Empty image"):
            geo.plan_image_transfers(g, simple_members({"dzImage": 0}))


class HardwareFreePrewriteTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.path, self.combination = build_archives(Path(tmp.name))

    def _attempt(self, pit):
        watch = SimulatedWatch(pit_data=pit)
        server = SimulatedServer(watch)
        with mock.patch.object(netodin.socket, "socket", return_value=server):
            with mock.patch.object(netodin, "format_progress"):
                netodin.flash_ap_package(str(self.path), auto_reboot=False,
                                         combination_path=str(self.combination))
        return watch

    def test_good_geometry_reaches_transfer_in_simulation(self):
        watch = self._attempt(fake_pit())
        self.assertEqual(len(watch.transfer_commands), 12 * 3)

    def test_zero_geometry_aborts_before_first_transfer(self):
        pit = replace_pit_field(fake_pit(), "dzImage", 24, 0)
        watch = SimulatedWatch(pit_data=pit)
        with mock.patch.object(netodin.socket, "socket", return_value=SimulatedServer(watch)):
            with self.assertRaises(SafetyError):
                netodin.flash_ap_package(str(self.path), auto_reboot=False,
                                         combination_path=str(self.combination))
        self.assertEqual(watch.transfer_commands, [])
        self.assertEqual(watch.raw_blocks, 0)

    def test_undersized_geometry_aborts_before_first_transfer(self):
        pit = replace_pit_field(fake_pit(), "dzImage", 24, 1)
        watch = SimulatedWatch(pit_data=pit)
        with mock.patch.object(netodin.socket, "socket", return_value=SimulatedServer(watch)):
            with self.assertRaises(SafetyError):
                netodin.flash_ap_package(str(self.path), auto_reboot=False,
                                         combination_path=str(self.combination))
        self.assertEqual(watch.transfer_commands, [])
        self.assertEqual(watch.raw_blocks, 0)


if __name__ == "__main__":
    unittest.main()
