"""Offline factory-partition safety and recovery-readiness simulations.

No watch, no factory backup contents, no transport sockets, no Odin writes.
"""
from __future__ import annotations

import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "installer"))
sys.path.insert(0, str(ROOT / "tests"))

from r800_recovery_readiness import (
    FAILURE_HANDLING, parse_all_pit_partitions,
    recovery_readiness, validate_factory_boundaries, main,
)
from r800_safety import SafetyError
from test_installer_guard import fake_pit
from test_recovery_audit import build_archives
from test_pit_geometry import replace_pit_field
from test_netodin_protocol import SimulatedWatch, SimulatedServer
import netodin


def with_partition(pit: bytes, *, name="CSA", filename="", identifier=99,
                   offset=250000, blocks=100, device_type=0) -> bytes:
    data = bytearray(pit)
    count = struct.unpack_from("<I", data, 4)[0]
    assert count < 127
    struct.pack_into("<I", data, 4, count + 1)
    entry = bytearray(132)
    struct.pack_into("<I", entry, 4, device_type)
    struct.pack_into("<I", entry, 8, identifier)
    struct.pack_into("<II", entry, 20, offset, blocks)
    entry[36:36 + len(name)] = name.encode("ascii")
    entry[68:68 + len(filename)] = filename.encode("ascii")
    data.extend(entry)
    return bytes(data)


class FactoryPartitionTests(unittest.TestCase):
    def test_no_factory_entries_cannot_prove_backup(self):
        status = validate_factory_boundaries(fake_pit())
        self.assertEqual(status["targets_inspected"], 12)
        self.assertEqual(status["protected_entries_visible"], 0)
        self.assertFalse(status["factory_data_read_or_modified"])

    def test_csa_and_cm_are_seen_without_factory_contents(self):
        data = with_partition(fake_pit(), name="CSA", identifier=98)
        data = with_partition(data, name="CM", filename="cm.bin", identifier=99,
                              offset=252000)
        status = validate_factory_boundaries(data)
        self.assertEqual(status["protected_entries_visible"], 2)
        self.assertEqual(status["protected_partition_labels"], ["CM", "CSA"])
        self.assertFalse(status["geometry_interpretation_verified_on_device"])

    def test_efs_name_is_protected(self):
        data = with_partition(fake_pit(), name="EFS", identifier=105)
        status = validate_factory_boundaries(data)
        self.assertIn("EFS", status["protected_partition_labels"])

    def test_protected_identifier_alias_without_filename_blocked(self):
        # Prior filename-only map does not see this kind of hidden PIT entry.
        data = with_partition(fake_pit(), name="CSA", identifier=80)
        with self.assertRaisesRegex(SafetyError, "identifier conflict"):
            validate_factory_boundaries(data)

    def test_protected_same_storage_range_blocked(self):
        data = with_partition(fake_pit(), name="CSA", identifier=99,
                              offset=0, blocks=128)
        with self.assertRaisesRegex(SafetyError, "overlap"):
            validate_factory_boundaries(data)

    def test_protected_other_device_bank_not_assumed_overlap(self):
        data = with_partition(fake_pit(), name="CSA", identifier=99,
                              offset=0, blocks=128, device_type=2)
        status = validate_factory_boundaries(data)
        self.assertEqual(status["protected_entries_visible"], 1)

    def test_target_partition_labeled_csa_blocked(self):
        data = bytearray(fake_pit())
        data[28 + 36:28 + 39] = b"CSA"
        with self.assertRaisesRegex(SafetyError, "Protected partition targeted"):
            validate_factory_boundaries(bytes(data))

    def test_truncated_pit_blocked(self):
        with self.assertRaises(SafetyError):
            validate_factory_boundaries(fake_pit()[:-1])

    def test_invalid_extra_device_type_blocked(self):
        data = with_partition(fake_pit(), name="CSA", device_type=18)
        with self.assertRaisesRegex(SafetyError, "device type"):
            validate_factory_boundaries(data)

    def test_hidden_partition_zero_file_name_is_examined(self):
        data = with_partition(fake_pit(), name="CM", filename="", identifier=100)
        entries = parse_all_pit_partitions(data)
        self.assertTrue(entries[-1]["protected"])
        self.assertEqual(entries[-1]["flash_filename"], "")

    def test_protected_classifier_no_substring_false_positive(self):
        # 'CMM' should not be misidentified as the protected 'CM'.
        data = with_partition(fake_pit(), name="CMM", identifier=100)
        status = validate_factory_boundaries(data)
        self.assertEqual(status["protected_entries_visible"], 0)


class OfflineRecoveryReadinessTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.folder = Path(tmp.name)
        self.package, self.combo = build_archives(self.folder)
        self.pit_file = self.folder / "saved.pit"
        self.pit_file.write_bytes(fake_pit())

    def test_structural_checks_never_authorize_flashing(self):
        report = recovery_readiness(self.package, self.pit_file, self.combo)
        self.assertEqual(report["decision"], "HOLD_HARDWARE_UNVERIFIED")
        for field in ("safe_to_flash", "can_recover_after_flash_failure",
                      "factory_backup_verified", "wired_recovery_verified",
                      "wireless_recovery_verified",
                      "retail_bootloader_compatibility_verified"):
            self.assertFalse(report[field])
        self.assertGreaterEqual(len(report["blockers"]), 6)

    def test_factory_partition_visibility_still_not_recovery_proof(self):
        self.pit_file.write_bytes(with_partition(fake_pit(), name="CSA"))
        report = recovery_readiness(self.package, self.pit_file, self.combo)
        self.assertFalse(report["safe_to_flash"])
        self.assertFalse(report["can_recover_after_flash_failure"])

    def test_overlapping_factory_partition_refused(self):
        self.pit_file.write_bytes(with_partition(fake_pit(), name="CM",
                                                  offset=0, blocks=100))
        with self.assertRaisesRegex(SafetyError, "overlap"):
            recovery_readiness(self.package, self.pit_file, self.combo)

    def test_reference_mismatch_refused(self):
        package, combo = build_archives(
            self.folder, altered={"ramdisk-recovery.img": b"modified"})
        with self.assertRaisesRegex(SafetyError, "differs"):
            recovery_readiness(package, self.pit_file, combo)

    def test_bad_pit_length_refused(self):
        self.pit_file.write_bytes(b"x")
        with self.assertRaisesRegex(SafetyError, "PIT size"):
            recovery_readiness(self.package, self.pit_file, self.combo)

    def test_cli_always_writes_hold_or_reject_json(self):
        path = self.folder / "readiness.json"
        self.assertEqual(main([
            "--package", str(self.package),
            "--pit-file", str(self.pit_file),
            "--combination", str(self.combo), "--report", str(path),
        ]), 0)
        data = json.loads(path.read_text())
        self.assertFalse(data["safe_to_flash"])
        self.assertEqual(data["decision"], "HOLD_HARDWARE_UNVERIFIED")
        self.pit_file.write_bytes(b"bad")
        self.assertEqual(main([
            "--package", str(self.package),
            "--pit-file", str(self.pit_file),
            "--combination", str(self.combo), "--report", str(path),
        ]), 2)
        failed = json.loads(path.read_text())
        self.assertFalse(failed["safe_to_flash"])
        self.assertEqual(failed["decision"], "REJECT_OFFLINE_EVIDENCE")

    def test_no_socket_used_for_readiness(self):
        import socket
        with mock.patch.object(socket, "socket",
                               side_effect=AssertionError("network accessed")):
            report = recovery_readiness(self.package, self.pit_file, self.combo)
        self.assertEqual(report["decision"], "HOLD_HARDWARE_UNVERIFIED")

    def test_never_automatically_retry_partial_flash(self):
        for state in FAILURE_HANDLING.values():
            self.assertFalse(state["automatic_retry"])

    def _simulate_live_pit(self, pit):
        watch = SimulatedWatch(pit_data=pit)
        with mock.patch.object(netodin.socket, "socket",
                               return_value=SimulatedServer(watch)):
            with mock.patch.object(netodin, "format_progress"):
                with self.assertRaises(SafetyError):
                    netodin.flash_ap_package(
                        str(self.package), combination_path=str(self.combo),
                        auto_reboot=False)
        self.assertEqual(watch.transfer_commands, [])
        self.assertEqual(watch.raw_blocks, 0)

    def test_installer_rejects_hidden_factory_identifier_collision_prewrite(self):
        self._simulate_live_pit(with_partition(
            fake_pit(), name="CSA", filename="", identifier=80))

    def test_installer_rejects_factory_block_overlap_prewrite(self):
        self._simulate_live_pit(with_partition(
            fake_pit(), name="CM", filename="", identifier=99,
            offset=0, blocks=100))


if __name__ == "__main__":
    unittest.main()
