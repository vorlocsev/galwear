"""Fail-closed checks: genuine full preflight must precede *any* network socket.

These tests use deliberately fake TAR/NZIT images and no device connections.
"""
from __future__ import annotations

from contextlib import redirect_stdout, redirect_stderr
import io
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "installer"))
sys.path.insert(0, str(ROOT / "tests"))

import netodin
from r800_safety import SafetyError
from test_recovery_audit import build_archives, nzit_image
from test_installer_guard import synthetic_archive


class ReferenceGateTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.path = Path(tmp.name)
        self.package, self.combo = build_archives(self.path)

    def test_direct_call_without_reference_refused_before_socket(self):
        with mock.patch.object(netodin.socket, "socket",
                               side_effect=AssertionError("socket opened")):
            with self.assertRaisesRegex(SafetyError, "REQUIRED"):
                netodin.flash_ap_package(str(self.package))

    def test_tampered_sboot_refused_before_socket(self):
        self.package, self.combo = build_archives(
            self.path, altered={"sboot.bin": b"different sboot"})
        with mock.patch.object(netodin.socket, "socket",
                               side_effect=AssertionError("socket opened")):
            with self.assertRaisesRegex(SafetyError, "sboot.bin differs"):
                netodin.flash_ap_package(
                    str(self.package), combination_path=str(self.combo))

    def test_recovery_kernel_mismatch_refused_before_socket(self):
        self.package, self.combo = build_archives(
            self.path, altered={"dzImage-recovery": nzit_image() + b"edited"})
        with mock.patch.object(netodin.socket, "socket",
                               side_effect=AssertionError("socket opened")):
            with self.assertRaisesRegex(SafetyError, "dzImage-recovery differs"):
                netodin.flash_ap_package(
                    str(self.package), combination_path=str(self.combo))

    def test_bad_active_kernel_refused_before_socket(self):
        self.package, self.combo = build_archives(self.path, bad_nzit=True)
        with mock.patch.object(netodin.socket, "socket",
                               side_effect=AssertionError("socket opened")):
            with self.assertRaisesRegex(SafetyError, "Invalid EXYN"):
                netodin.flash_ap_package(
                    str(self.package), combination_path=str(self.combo))

    def test_good_reference_reaches_socket_gate_only(self):
        class ReachedSocket(Exception):
            pass
        with mock.patch.object(netodin.socket, "socket", side_effect=ReachedSocket):
            with self.assertRaises(ReachedSocket):
                netodin.flash_ap_package(
                    str(self.package), combination_path=str(self.combo))

    def test_cli_live_needs_confirmation_and_reference(self):
        with mock.patch.object(netodin.socket, "socket",
                               side_effect=AssertionError("socket opened")):
            with mock.patch.object(sys, "argv",
                                   ["netodin.py", "--ap", str(self.package),
                                    "--confirm-r800"]):
                with redirect_stderr(io.StringIO()):
                    with self.assertRaises(SystemExit) as exit_info:
                        netodin.main()
                self.assertEqual(exit_info.exception.code, 2)

    def test_offline_full_preflight_never_opens_socket(self):
        with mock.patch.object(netodin.socket, "socket",
                               side_effect=AssertionError("socket opened")):
            with mock.patch.object(sys, "argv",
                                   ["netodin.py", "--preflight-only",
                                    "--ap", str(self.package),
                                    "--combination-reference", str(self.combo)]):
                with redirect_stdout(io.StringIO()) as captured:
                    netodin.main()
                self.assertIn("reference comparison", captured.getvalue())

    def test_offline_full_preflight_rejects_bad_reference(self):
        self.package, self.combo = build_archives(
            self.path, altered={"ramdisk-recovery.img": b"changed"})
        with mock.patch.object(netodin.socket, "socket",
                               side_effect=AssertionError("socket opened")):
            with mock.patch.object(sys, "argv",
                                   ["netodin.py", "--preflight-only",
                                    "--ap", str(self.package),
                                    "--combination-reference", str(self.combo)]):
                with redirect_stdout(io.StringIO()):
                    with self.assertRaises(SafetyError):
                        netodin.main()

    def test_old_archive_only_preflight_kept_read_only(self):
        with mock.patch.object(netodin.socket, "socket",
                               side_effect=AssertionError("socket opened")):
            with mock.patch.object(sys, "argv",
                                   ["netodin.py", "--preflight-only",
                                    "--ap", str(self.package)]):
                with redirect_stdout(io.StringIO()) as output:
                    netodin.main()
                self.assertIn("NOT verified", output.getvalue())

    def test_live_flashing_is_not_marked_safe_in_logs(self):
        code = (ROOT / "installer" / "netodin.py").read_text(encoding="utf-8")
        self.assertIn("does not prove Samsung provenance", code)
        self.assertIn("combination-reference", code)


if __name__ == "__main__":
    unittest.main()
