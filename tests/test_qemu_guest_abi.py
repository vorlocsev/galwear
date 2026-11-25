"""Synthetic evidence checks for virt guest ABI mode."""
from pathlib import Path
import hashlib
import json
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "build"))
import r800_qemu_guest_abi as a

LOG = (a.EXPECTED + a.START + b"\n" + a.ABI_EXPECTED + a.END + b"\n"
       + a.HEARTBEAT_PREFIX + b"00000001\n")


class GuestAbiTests(unittest.TestCase):
    def test_complete_abi(self):
        report = a.inspect_abi(LOG)
        self.assertTrue(report["guest_pid1_reported"])
        self.assertTrue(report["shared_memory_roundtrip"])

    def test_missing_pid1_marker(self):
        with self.assertRaisesRegex(ValueError, "markers"):
            a.inspect_abi(LOG.replace(a.START, b""))

    def test_missing_abi_stage(self):
        with self.assertRaisesRegex(ValueError, "sequence"):
            a.inspect_abi(LOG.replace(a.ABI_EXPECTED.splitlines()[0], b""))

    def test_heartbeat_before_complete(self):
        with self.assertRaisesRegex(ValueError, "Heartbeat before"):
            a.inspect_abi(LOG.replace(a.END + b"\n", b"") + a.END + b"\n")

    def test_abi_failure_rejected(self):
        with self.assertRaisesRegex(ValueError, "sequence"):
            a.inspect_abi(LOG.replace(a.END, b"r800-abi: FAIL mmap\n" + a.END))

    def test_baseline_kernel_hash_and_status(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            image = root / "Image"
            raw = bytearray(128)
            raw[56:60] = b"ARM\x64"
            image.write_bytes(raw)
            evidence = root / "baseline.json"
            digest = hashlib.sha256(raw).hexdigest()
            report = {"status": "VIRT_EMBEDDED_PID1_BOOT_ONLY",
                      "initramfs_mode": "embedded", "generic_kernel_sha256": digest,
                      "guest_progress_after_marker_verified": True,
                      "safe_to_flash": False}
            evidence.write_text(json.dumps(report))
            self.assertEqual(a.verify_baseline(evidence, image), digest)
            for key, value in (("status", "REJECT"), ("generic_kernel_sha256", "bad"),
                               ("safe_to_flash", True), ("initramfs_mode", "external"),
                               ("guest_progress_after_marker_verified", False)):
                with self.subTest(key=key):
                    evidence.write_text(json.dumps({**report, key: value}))
                    with self.assertRaisesRegex(ValueError, "does not match"):
                        a.verify_baseline(evidence, image)


if __name__ == "__main__":
    unittest.main()
