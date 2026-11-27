"""Synthetic section and block hash diagnostics; no kernel build required."""
import hashlib
from pathlib import Path
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "build"))
import r800_kernel_diff_evidence as diag


def elf(payload):
    data = bytearray(512)
    data[:6] = b"\x7fELF\x02\x01"
    struct.pack_into("<H", data, 18, 183)
    struct.pack_into("<Q", data, 40, 64)
    struct.pack_into("<HHH", data, 58, 64, 3, 1)
    names = b"\0.shstrtab\0.text\0"
    struct.pack_into("<IIQQQQIIQQ", data, 128, 1, 3, 0, 0, 256, len(names), 0, 0, 1, 0)
    struct.pack_into("<IIQQQQIIQQ", data, 192, 11, 1, 2, 4096, 320, len(payload), 0, 0, 1, 0)
    data[256:256+len(names)] = names
    data[320:320+len(payload)] = payload
    return bytes(data)


class KernelDiffEvidenceTests(unittest.TestCase):
    def test_section_content_only(self):
        a = diag.sections(elf(b"abc"))
        b = diag.sections(elf(b"abd"))
        self.assertEqual(list(a), [".text"])
        self.assertEqual(a[".text"]["address"], 4096)
        self.assertEqual(a[".text"]["sha256"], hashlib.sha256(b"abc").hexdigest())
        self.assertNotEqual(a[".text"], b[".text"])

    def test_wrong_elf_rejected(self):
        with self.assertRaises(ValueError):
            diag.sections(b"not ELF")

    def test_image_block_localization(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            image = root / "arch/arm64/boot/Image"
            image.parent.mkdir(parents=True)
            data = bytearray(diag.BLOCK + 10)
            data[56:60] = b"ARM\x64"
            image.write_bytes(data)
            (root / "vmlinux").write_bytes(elf(b"abc"))
            a = diag.snapshot(root)
            data[-1] = 1
            image.write_bytes(data)
            b = diag.snapshot(root)
            self.assertEqual(a["blocks"][0], b["blocks"][0])
            self.assertNotEqual(a["blocks"][1], b["blocks"][1])
            self.assertNotEqual(a["image_sha256"], b["image_sha256"])
            self.assertEqual(a["sections"], b["sections"])
            self.assertFalse(a["safe_to_flash"])


class KernelDiffComparisonTests(unittest.TestCase):
    def setUp(self):
        import r800_reproducibility_audit as audit
        self.a = {"schema": "galwear-kernel-diagnostic-v1", "safe_to_flash": False,
                  "image_sha256": "11" * 32, "image_bytes": diag.BLOCK + 10,
                  "block_bytes": diag.BLOCK, "blocks": ["22" * 32, "33" * 32],
                  "sections": diag.sections(elf(b"abc"))}
        import copy
        self.b = copy.deepcopy(self.a)
        self.ma = {field: "44" * 32 for field in audit.COMPARE_FIELDS
                   if field.endswith("_sha256")}
        self.ma.update(schema=audit.SCHEMA, status="ONE_BUILD_EVIDENCE_ONLY",
                       run_id=33, run_attempt=1, runner_replica="a",
                       galwear_commit="ab" * 20, source_commit=audit.BASE,
                       container_image_id="sha256:" + "cd" * 32,
                       compiler="19.1.4", linker="19.1.4",
                       image_sha256=self.a["image_sha256"], image_bytes=self.a["image_bytes"],
                       kernel_compiled=True, cpio_verified=True, kernel_boot_tested=False,
                       reproducibility_proven=False, safe_to_flash=False)
        self.mb = dict(self.ma, runner_replica="b")

    def compare(self):
        return diag.compare(self.a, self.b, self.ma, self.mb)

    def test_equal(self):
        result = self.compare()
        self.assertEqual(result["status"], "IMAGE_HASH_MATCH")
        self.assertEqual(result["different_blocks"], 0)
        self.assertEqual(result["different_sections"], {})
        self.assertFalse(result["safe_to_flash"])

    def test_changed_block_and_section(self):
        self.b["image_sha256"] = self.mb["image_sha256"] = "55" * 32
        self.b["blocks"][1] = "66" * 32
        self.b["sections"] = diag.sections(elf(b"abd"))
        result = self.compare()
        self.assertEqual(result["status"], "IMAGE_HASH_MISMATCH")
        self.assertEqual(result["different_block_offsets"], [diag.BLOCK])
        self.assertEqual(list(result["different_sections"]), [".text"])

    def test_unbound_digest_rejected(self):
        self.b["image_sha256"] = "55" * 32
        with self.assertRaisesRegex(ValueError, "not bound"):
            self.compare()

    def test_wrong_attempt_rejected(self):
        self.mb["run_attempt"] = 2
        with self.assertRaisesRegex(ValueError, "identity mismatch"):
            self.compare()

    def test_same_replica_rejected(self):
        self.mb["runner_replica"] = "a"
        with self.assertRaisesRegex(ValueError, "distinct matrix replicas"):
            self.compare()

    def test_truncated_block_list_rejected(self):
        self.b["blocks"].pop()
        with self.assertRaisesRegex(ValueError, "block count"):
            self.compare()

    def test_inconsistent_whole_hash_rejected(self):
        self.b["blocks"][0] = "77" * 32
        with self.assertRaisesRegex(ValueError, "Inconsistent"):
            self.compare()


if __name__ == "__main__":
    unittest.main()
