import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "build"))
import r800_arm32_runtime_extract as runtime


def mkimage(tree, image):
    with image.open("wb") as stream:
        stream.truncate(32*1024**2)
    subprocess.run(["mke2fs", "-q", "-F", "-t", "ext4", "-d", str(tree), str(image)],
                   check=True, capture_output=True)


class Arm32RuntimeExtractTests(unittest.TestCase):
    def test_rootless_extraction_and_digest_gate(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            rt = root/"runtime"
            rt.mkdir()
            for name, guest in runtime.FILES.items():
                dest = rt/guest.lstrip("/")
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(name.encode())
            payload = root/"payload.img"
            mkimage(rt, payload)
            system = root/"system"
            (system/"apex").mkdir(parents=True)
            (system/"lib").mkdir()
            (system/"lib/liblog.so").write_bytes(b"liblog.so")
            with zipfile.ZipFile(system/"apex/com.android.runtime.apex", "w", zipfile.ZIP_DEFLATED) as z:
                z.write(payload, "apex_payload.img")
            image = root/"system.img"
            mkimage(system, image)
            expected = runtime.image_info(image)["sha256"]
            out = root/"out"
            # Synthetic member bytes: isolate extraction/provenance test from
            # the existing real ELF inspector. Never claim Bionic execution.
            def fake_check(path, library=False):
                return path.read_bytes(), {"elf_type": "ET_DYN", "needed": [],
                                           "soname": path.name if library else None}
            with patch.object(runtime, "check", side_effect=fake_check):
                report = runtime.extract(image, expected, out)
            self.assertEqual(report["status"], "ARM32_BIONIC_RUNTIME_EXTRACTED_STATIC_ONLY")
            pins = json.loads((out/"runtime-manifest.json").read_text())
            self.assertEqual(set(pins), set(runtime.RUNTIME))
            self.assertEqual(pins["libc.so"], hashlib.sha256(b"libc.so").hexdigest())
            self.assertEqual(report["files"]["liblog.so"]["origin"], "system")
            self.assertFalse(report["runtime_verified"])
            self.assertEqual(runtime.image_info(image)["sha256"], expected)
            with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
                runtime.extract(image, "0"*64, root/"wrong")
            self.assertFalse((root/"wrong").exists())
            with self.assertRaisesRegex(ValueError, "Invalid little-endian ELF"):
                runtime.extract(image, expected, root/"invalid")
            self.assertFalse((root/"invalid").exists())

    def test_flattened_apex_and_xz_bounds(self):
        import lzma
        from r800_phh_runtime_reference import expand
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            tree = root/"tree"
            (tree/"lib").mkdir(parents=True)
            (tree/"lib/liblog.so").write_bytes(b"liblog.so")
            for name, guest in runtime.FILES.items():
                dest = tree/"apex/com.android.runtime"/guest.lstrip("/")
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(name.encode())
            image = root/"system.img"
            mkimage(tree, image)
            expected = runtime.image_info(image)["sha256"]
            def fake_check(path, library=False):
                return path.read_bytes(), {"elf_type": "ET_DYN", "needed": [],
                                           "soname": path.name if library else None}
            with patch.object(runtime, "check", side_effect=fake_check):
                report = runtime.extract(image, expected, root/"out")
            self.assertEqual(report["apex_layout"], "FLATTENED_APEX")
            self.assertIsNone(report["apex_sha256"])
            archive = root/"fixture.xz"
            archive.write_bytes(lzma.compress(b"fixture"))
            size = archive.stat().st_size
            result = expand(archive, root/"expanded", expected_size=size, limit=7)
            self.assertEqual(result["system_sha256"], hashlib.sha256(b"fixture").hexdigest())
            good = expand(archive, root/"pinned", expected_size=size, limit=7,
                          expected_sha=hashlib.sha256(archive.read_bytes()).hexdigest(),
                          expected_system_sha=hashlib.sha256(b"fixture").hexdigest(),
                          expected_system_bytes=7)
            self.assertEqual(good, result)
            with self.assertRaisesRegex(ValueError, "Reference asset SHA-256"):
                expand(archive, root/"wrong-pin", expected_size=size, expected_sha="0"*64)
            self.assertFalse((root/"wrong-pin").exists())
            with self.assertRaisesRegex(ValueError, "Expanded system SHA-256"):
                expand(archive, root/"wrong-system", expected_size=size, expected_system_sha="0"*64)

            with self.assertRaisesRegex(ValueError, "exceeds limit"):
                expand(archive, root/"oversized", expected_size=size, limit=6)

    def test_linker_soname_dependency_is_not_external_library(self):
        from r800_hal_dlopen_probe import runtime_dependencies
        libc = {"elf_type": "ET_DYN", "needed": ["libdl.so", "ld-android.so"]}
        runtime_dependencies("libc.so", libc, "ld-android.so")
        with self.assertRaisesRegex(ValueError, "ld-android.so"):
            runtime_dependencies("libc.so", libc, None)
        with self.assertRaisesRegex(ValueError, "libunknown.so"):
            runtime_dependencies("libc.so", {"elf_type": "ET_DYN",
                "needed": ["ld-android.so", "libunknown.so"]}, "ld-android.so")
        with self.assertRaisesRegex(ValueError, "Unexpected ARM32 linker"):
            runtime_dependencies("linker", {"elf_type": "ET_DYN",
                "needed": ["libc.so"]}, "ld-android.so")


if __name__ == "__main__":
    unittest.main()
