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


if __name__ == "__main__":
    unittest.main()
