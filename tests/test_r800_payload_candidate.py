"""Synthetic curated payload tests. No real firmware or device state."""
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "build"))
import r800_payload_candidate as payload
from test_android_linker_audit import fixture
from test_r800_stage_components import arm_fixture


class PayloadCandidateTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.src = self.root / "curated"
        self.rel = self.root / "release"
        self.out = self.root / "candidate.tar"
        self.put(self.src, "android/system.sqfs", b"hsqs" + bytes(2048))
        self.put(self.src, "android/persistent.img", bytes(1024 * 1024))
        for name in payload.HALS:
            self.put(self.src, "hwc/" + name, fixture("arm"))
        for name in payload.BINS:
            p = self.put(self.src, "bin/" + name, arm_fixture() if name in payload.WIFI_TOOLS else b"fixture")
            p.chmod(0o755)
        for name in payload.DIRS:
            (self.src / name).mkdir()
        for name in payload.RADIO_FILES:
            data = fixture("arm") if name.endswith(".so") else b"synthetic radio input"
            self.put(self.src, name, data)
        self.put(self.rel, "src/vendor/libbt/bt_vendor.conf", b"synthetic radio input")
        for name in payload.REQUIRED:
            self.put(self.src, name, b"synthetic patch\0" if name.endswith(".txt") else b"synthetic firmware")
        for name in payload.SINGLE:
            self.put(self.src, name, b"fixture")
        for name, size in payload.ASSET_SIZES.items():
            self.put(self.src, name, bytes(size))
        for name in payload.CHARGER_TOOLS:
            self.put(self.src, name, b"fixture").chmod(0o755)
        for name in payload.SCRIPTS:
            self.put(self.rel, "payload/" + name, b"#!/bin/sh\n")
        self.put(self.rel, "src/tools/sensors/tzchroot.sh", b"#!/bin/sh\n")

    def put(self, root, name, data):
        p = root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
        return p

    def build(self):
        return payload.build(self.src, self.rel, self.out)

    def test_curated_only(self):
        self.put(self.src, "android/DEV", b"")
        self.put(self.src, "android/userdata.img", b"not included")
        self.put(self.src, "android/unlisted/private.db", b"not included")
        report = self.build()
        self.assertFalse(report["safe_to_flash"])
        self.assertFalse(report["device_state_absence_verified"])
        with tarfile.open(self.out) as tar:
            names = tar.getnames()
            self.assertIn("r800dev/android/BOOT_ANDROID", names)
            self.assertNotIn("r800dev/android/DEV", names)
            self.assertNotIn("r800dev/android/userdata.img", names)
            self.assertNotIn("r800dev/android/unlisted/private.db", names)

    def test_wrong_wifi_tool_abi(self):
        self.put(self.src, "bin/iw", fixture("arm64"))
        with self.assertRaisesRegex(ValueError, "ARM32 ELF"):
            self.build()

    def test_obsolete_musl_tree_excluded(self):
        self.put(self.src, "root/lib/ld-musl-aarch64.so.1", b"obsolete")
        report = self.build()
        self.assertFalse(report["safe_to_flash"])
        with tarfile.open(self.out) as tar:
            self.assertFalse(any(n.startswith("r800dev/root/") for n in tar.getnames()))

    def test_missing_peripheral_firmware(self):
        (self.src / "fw/vts.bin").unlink()
        with self.assertRaisesRegex(ValueError, "Missing peripheral firmware"):
            self.build()

    def test_missing_wifi_firmware(self):
        (self.src / "fw/bcmdhd_sta.bin").unlink()
        with self.assertRaisesRegex(ValueError, "Missing radio input"):
            self.build()
        self.assertFalse(self.out.exists())

    def test_wrong_bluetooth_abi(self):
        self.put(self.src, "fw/bt/libbt-vendor.so", fixture("arm64"))
        with self.assertRaisesRegex(ValueError, "ARM32 Bluetooth"):
            self.build()

    def test_changed_bluetooth_configuration(self):
        self.put(self.src, "fw/bt/bt_vendor.conf", b"changed")
        with self.assertRaisesRegex(ValueError, "repository profile"):
            self.build()

    def test_bad_charger_asset_size(self):
        self.put(self.src, "charger/d0.rgb", b"bad")
        with self.assertRaisesRegex(ValueError, "Invalid display asset size"):
            self.build()

    def test_missing_charger_asset(self):
        (self.src / "charger/bolt.rgb").unlink()
        with self.assertRaisesRegex(ValueError, "Missing display asset"):
            self.build()

    def test_mismatched_wpcd(self):
        self.put(self.src, "charger/wpcd", b"different").chmod(0o755)
        with self.assertRaisesRegex(ValueError, "WPCD bytes differ"):
            self.build()

    def test_missing_hal(self):
        (self.src / "hwc/gps.r800.so").unlink()
        with self.assertRaises(FileNotFoundError):
            self.build()
        self.assertFalse(self.out.exists())

    def test_wrong_hal_abi(self):
        self.put(self.src, "hwc/gps.r800.so", fixture("arm64"))
        with self.assertRaisesRegex(ValueError, "ARM32 HAL"):
            self.build()

    def test_invalid_system(self):
        self.put(self.src, "android/system.sqfs", b"wrong")
        with self.assertRaisesRegex(ValueError, "system image magic"):
            self.build()

    def test_recursive_state_rejected(self):
        self.put(self.src, "fw/accounts.db", b"fixture")
        with self.assertRaisesRegex(ValueError, "State/debug"):
            self.build()

    def test_no_overwrite(self):
        self.out.write_bytes(b"keep")
        with self.assertRaisesRegex(ValueError, "already exists"):
            self.build()
        self.assertEqual(self.out.read_bytes(), b"keep")

    def test_unsafe_symlink(self):
        (self.src / "tzlite/escape").symlink_to("/etc/passwd")
        with self.assertRaisesRegex(ValueError, "Unsafe payload symlink"):
            self.build()


if __name__ == "__main__":
    unittest.main()
