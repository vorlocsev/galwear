"""Synthetic ext4/APEX extraction tests, never using real donor firmware."""
from pathlib import Path
import hashlib
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import warnings
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "build"))
import r800_android_runtime_extract as a


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class RuntimeTests(unittest.TestCase):
    def test_digest_mismatch(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            donor = root / "donor"
            donor.write_bytes(b"not android")
            with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
                a.extract(donor, "0" * 64, root / "out")
            self.assertFalse((root / "out").exists())

    def test_missing_apex_payload(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            apex = root / "donor.apex"
            with zipfile.ZipFile(apex, "w") as z:
                z.writestr("original_apex", b"CAPEX unsupported")
            with self.assertRaisesRegex(ValueError, "exactly one"):
                a.extract_payload(apex, root / "payload")

    def test_duplicate_payload(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            apex = root / "donor.apex"
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                with zipfile.ZipFile(apex, "w") as z:
                    z.writestr("apex_payload.img", b"one")
                    z.writestr("apex_payload.img", b"two")
            with self.assertRaisesRegex(ValueError, "exactly one"):
                a.extract_payload(apex, root / "payload")

    def test_sparse_expansion_limit(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            donor = root / "system.img"
            header = bytearray(28)
            header[:4] = a.SPARSE_MAGIC
            header[4:6] = (1).to_bytes(2, "little")
            header[8:10] = (28).to_bytes(2, "little")
            header[10:12] = (12).to_bytes(2, "little")
            header[12:16] = (4096).to_bytes(4, "little")
            header[16:20] = (a.MAX_SYSTEM // 4096 + 1).to_bytes(4, "little")
            donor.write_bytes(header)
            with self.assertRaisesRegex(ValueError, "expansion outside"):
                a.unpack_system(donor, root)

    @unittest.skipUnless(shutil.which("debugfs") and shutil.which("mke2fs"), "e2fsprogs required")
    def test_synthetic_ext4_apex_and_system(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            tree = root / "tree"
            for relative in a.FILES:
                target = tree / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(("fixture:" + relative).encode())
            payload = root / "payload.img"
            subprocess.run(["mke2fs", "-q", "-t", "ext4", "-d", str(tree),
                            "-F", str(payload), "8192"], check=True, capture_output=True)
            donor = root / "runtime.apex"
            with zipfile.ZipFile(donor, "w") as z:
                z.write(payload, "apex_payload.img")
                z.writestr("../../ignored", b"not extracted")
            system_tree = root / "system"
            (system_tree / "apex").mkdir(parents=True)
            shutil.copyfile(donor, system_tree / "apex/com.android.runtime.apex")
            system = root / "system.img"
            subprocess.run(["mke2fs", "-q", "-t", "ext4", "-d", str(system_tree),
                            "-F", str(system), "32768"], check=True, capture_output=True)

            def fake_elf(path, readelf):
                return {"elf_type": 3, "interpreter": None, "needed": [],
                        "soname": None if path.name == "linker64" else path.name,
                        "sha256": sha(path)}
            for index, source in enumerate((donor, system)):
                with self.subTest(source=source.name):
                    out = root / f"out{index}"
                    with patch.object(a, "inspect_elf", side_effect=fake_elf):
                        result = a.extract(source, sha(source), out)
                    self.assertEqual(result["status"], "ANDROID_RUNTIME_EXTRACTED_STATIC_ONLY")
                    self.assertFalse(result["dynamic_android_linker_tested"])
                    for relative in a.FILES:
                        self.assertEqual((out / a.RUNTIME / relative).read_bytes(),
                                         (tree / relative).read_bytes())
                    self.assertEqual((out / "system/bin/linker64").resolve(),
                                     (out / a.RUNTIME / "bin/linker64").resolve())
                    self.assertFalse((root / "ignored").exists())


if __name__ == "__main__":
    unittest.main()
