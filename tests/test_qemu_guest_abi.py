"""Synthetic evidence checks for virt guest ABI mode."""
from pathlib import Path
import hashlib
import json
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "build"))
import r800_qemu_guest_abi as a

LOG = (a.EXPECTED + a.START + b"\n" + a.ABI_EXPECTED + b"\n".join(a.BINDER_EXPECTED) + b"\n" + b"\n".join(a.SHMEM_EXPECTED) + b"\n" + a.END + b"\n"
       + a.HEARTBEAT_PREFIX + b"00000001\n")


class GuestAbiTests(unittest.TestCase):
    def test_complete_abi(self):
        report = a.inspect_abi(LOG)
        self.assertTrue(report["guest_pid1_reported"])
        self.assertTrue(report["shared_memory_roundtrip"])
        self.assertTrue(report["binder_transactions_tested"])
        self.assertTrue(report["ashmem_roundtrip_reported"])
        self.assertTrue(report["memfd_seals_reported"])
        self.assertEqual(report["binder_roundtrip_context"], "binder")

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

    def test_missing_binder_device(self):
        with self.assertRaisesRegex(ValueError, "Binder diagnostic sequence"):
            a.inspect_abi(LOG.replace(a.BINDER_EXPECTED[1], b""))

    def test_wrong_binder_version(self):
        with self.assertRaisesRegex(ValueError, "Binder diagnostic sequence"):
            a.inspect_abi(LOG.replace(b"version=8", b"version=7", 1))

    def test_binder_after_completion(self):
        with self.assertRaisesRegex(ValueError, "outside ABI completion"):
            a.inspect_abi(LOG.replace(a.END + b"\n", b"").replace(a.BINDER_EXPECTED[0], a.END + b"\n" + a.BINDER_EXPECTED[0]))

    def test_missing_binder_roundtrip(self):
        with self.assertRaisesRegex(ValueError, "Binder diagnostic sequence"):
            a.inspect_abi(LOG.replace(a.BINDER_EXPECTED[-2], b""))

    def test_roundtrip_requires_distinct_processes(self):
        with self.assertRaisesRegex(ValueError, "Binder diagnostic sequence"):
            a.inspect_abi(LOG.replace(b"distinct-processes=1", b"distinct-processes=0"))

    def test_binder_failure_after_roundtrip(self):
        with self.assertRaisesRegex(ValueError, "Binder diagnostic sequence"):
            a.inspect_abi(LOG.replace(a.BINDER_EXPECTED[-1], b"r800-binder: FAIL transaction roundtrip"))

    def test_missing_shared_memory_stage(self):
        for marker in a.SHMEM_EXPECTED:
            with self.subTest(marker=marker):
                with self.assertRaisesRegex(ValueError, "shared memory diagnostic sequence"):
                    a.inspect_abi(LOG.replace(marker, b""))

    def test_memfd_seals_failure(self):
        with self.assertRaisesRegex(ValueError, "shared memory diagnostic sequence"):
            a.inspect_abi(LOG.replace(b"seals=PASS", b"seals=FAIL"))

    def test_shmem_after_completion(self):
        with self.assertRaisesRegex(ValueError, "outside ABI completion"):
            a.inspect_abi(LOG.replace(a.END + b"\n", b"").replace(a.SHMEM_EXPECTED[0], a.END + b"\n" + a.SHMEM_EXPECTED[0]))

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
