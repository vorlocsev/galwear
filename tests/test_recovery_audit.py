"""Synthetic offline tests: no watch, no Samsung/Google firmware required."""
from __future__ import annotations

import hashlib
import io
from pathlib import Path
import struct
import sys
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "installer"))
from r800_recovery_audit import audit_release, COPIED_FROM_COMBINATION
from r800_safety import EXPECTED_IMAGES, SafetyError

NZIT_MAGIC = 0x54495A4E
EXYN_MAGIC = 0x4E595845


def nzit_image(*, corrupt_dtb=False) -> bytes:
    kernel = b"k" * 2048
    dtb = b"test"
    # EXYN table: header (12), one entry (20), payload (4)
    table = struct.pack("<III", 0 if corrupt_dtb else EXYN_MAGIC, 1, 1)
    table += struct.pack("<5I", 9110, 0, 0, 32, len(dtb)) + dtb
    header = struct.pack("<7I", NZIT_MAGIC, 32768, len(kernel),
                         len(kernel) + 32768, len(table), 0, 2048)
    return header.ljust(2048, b"\0") + kernel + table + b"1" * 272


def build_archives(folder: Path, *, altered=None, missing_combination=None, bad_nzit=False,
                   package_bad_md5=False):
    altered = altered or {}
    package = folder / "R800-WearOS.tar.md5"
    combo = folder / "COMBINATION-FT40_R800XXU1ARI2_noCM.tar.md5"
    base = {
        n: nzit_image() if n in ("dzImage", "dzImage-recovery") else (n + " original").encode()
        for n in EXPECTED_IMAGES
    }
    for n in ("dzImage", "dzImage-recovery"):
        base[n] = nzit_image()
    with tarfile.open(combo, "w") as archive:
        for name in COPIED_FROM_COMBINATION:
            if name == missing_combination:
                continue
            payload = base[name]
            member = tarfile.TarInfo(name)
            member.size = len(payload)
            archive.addfile(member, io.BytesIO(payload))
    with tarfile.open(package, "w") as archive:
        for name in EXPECTED_IMAGES:
            payload = altered.get(name, base[name])
            if name == "dzImage" and bad_nzit:
                payload = nzit_image(corrupt_dtb=True)
            member = tarfile.TarInfo(name)
            member.size = len(payload)
            archive.addfile(member, io.BytesIO(payload))
    archive_data = package.read_bytes()
    md5 = hashlib.md5(archive_data).hexdigest()
    if package_bad_md5:
        md5 = "0" * 32
    package.write_bytes(archive_data + (md5 + "  R800-WearOS.tar\n").encode())
    return package, combo


class RecoveryAuditTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name)

    def test_identical_reference_components_pass(self):
        package, combo = build_archives(self.path)
        report = audit_release(package, combo)
        self.assertEqual(len(report["checks"]), 8)
        self.assertEqual(report["nzit"]["dzImage"]["dtb_entries"], 1)
        self.assertFalse(report["device_compatibility_verified"])
        self.assertFalse(report["source_authenticity_verified"])

    def test_reject_modified_sboot(self):
        package, combo = build_archives(self.path, altered={"sboot.bin": b"tampered"})
        with self.assertRaisesRegex(SafetyError, "sboot.bin differs"):
            audit_release(package, combo)

    def test_reject_modified_recovery_kernel(self):
        package, combo = build_archives(self.path, altered={"dzImage-recovery": nzit_image() + b"tamper"})
        with self.assertRaisesRegex(SafetyError, "dzImage-recovery differs"):
            audit_release(package, combo)

    def test_reject_modified_recovery_ramdisk(self):
        package, combo = build_archives(self.path, altered={"ramdisk-recovery.img": b"different"})
        with self.assertRaisesRegex(SafetyError, "ramdisk-recovery.img differs"):
            audit_release(package, combo)

    def test_reject_invalid_nzit(self):
        package, combo = build_archives(self.path, bad_nzit=True)
        with self.assertRaisesRegex(SafetyError, "Invalid EXYN"):
            audit_release(package, combo)

    def test_reject_missing_combination_file(self):
        package, combo = build_archives(self.path, missing_combination="sboot.bin")
        with self.assertRaisesRegex(SafetyError, "Missing combination members"):
            audit_release(package, combo)

    def test_reject_bad_archive_md5(self):
        package, combo = build_archives(self.path, package_bad_md5=True)
        with self.assertRaisesRegex(SafetyError, "Firmware MD5 mismatch"):
            audit_release(package, combo)

    def test_cli_generates_report(self):
        from r800_recovery_audit import main
        package, combo = build_archives(self.path)
        report = self.path / "audit.json"
        self.assertEqual(main(["--package", str(package),
                               "--combination", str(combo),
                               "--report", str(report)]), 0)
        self.assertIn("source_authenticity_verified", report.read_text())


if __name__ == "__main__":
    unittest.main()
