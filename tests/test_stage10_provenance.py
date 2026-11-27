"""Stage 10: synthetic-only input provenance and build recipe regressions.

Never runs root, builds firmware, mounts images or connects to a watch.
"""
from __future__ import annotations

import hashlib
import io
from pathlib import Path
import shutil
import sys
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "installer"))
sys.path.insert(0, str(ROOT / "tests"))

import r800_build_provenance as provenance
from r800_safety import SafetyError
from test_recovery_audit import build_archives, nzit_image


def write_tar(path: Path, files: dict[str, bytes], *,
              extra_symlink=None, extra_dir=None):
    with tarfile.open(path, "w") as archive:
        directory = tarfile.TarInfo("r800dev/")
        directory.type = tarfile.DIRTYPE
        archive.addfile(directory)
        for name, content in files.items():
            member = tarfile.TarInfo(name)
            member.size = len(content)
            archive.addfile(member, io.BytesIO(content))
        if extra_dir:
            member = tarfile.TarInfo(extra_dir)
            member.type = tarfile.DIRTYPE
            archive.addfile(member)
        if extra_symlink:
            name, target = extra_symlink
            member = tarfile.TarInfo(name)
            member.type = tarfile.SYMTYPE
            member.linkname = target
            archive.addfile(member)


class Stage10Tests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.dir = Path(temporary.name)
        self.images = self.dir / "images"
        (self.images / "samsung").mkdir(parents=True)
        (self.images / "boot").mkdir()
        for rel in provenance.SOURCE_FILES:
            p = self.dir / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(("synthetic source: " + rel).encode())
        package, combo = build_archives(self.dir)
        shutil.move(str(package), str(self.images / package.name))
        # Add combination's user/csc components to the synthetic fixture.
        with tarfile.open(combo, "a") as tar:
            for n in ("user.img", "csc.img"):
                data = (n + " fixture").encode()
                m = tarfile.TarInfo(n)
                m.size = len(data)
                tar.addfile(m, io.BytesIO(data))
        shutil.move(str(combo), str(self.images / "samsung" / combo.name))
        (self.images / "boot" / "r800-boot.img").write_bytes(nzit_image())
        vendor = bytearray(2048)
        vendor[1080:1082] = b"\x53\xef"
        (self.images / "vendor.img").write_bytes(vendor)
        self.payload = self.images / "payload.tar"
        self.payload_files = {
            "r800dev/start.sh": b"#!/bin/sh\n",
            "r800dev/android-helper.sh": b"#!/bin/sh\n",
            "r800dev/android/persistent.img": bytes(1024 * 1024),
        }
        write_tar(self.payload, self.payload_files)

    def test_valid_synthetic_prebuild_has_sha256_and_no_safety_claims(self):
        evidence = provenance.prebuild(self.dir)
        self.assertEqual(evidence["status"], "PREBUILD_INPUTS_CHECKED")
        self.assertEqual(len(evidence["sources"]), len(provenance.SOURCE_FILES))
        self.assertEqual(len(evidence["inputs"]), len(provenance.IMAGE_FILES))
        self.assertFalse(evidence["safe_to_flash"])
        self.assertFalse(evidence["source_authenticity_verified"])
        for item in evidence["inputs"].values():
            self.assertEqual(len(item["sha256"]), 64)

    def test_valid_synthetic_finalization_detects_release_members(self):
        before = provenance.prebuild(self.dir)
        evidence = provenance.finalize(self.dir, before)
        self.assertEqual(evidence["status"], "RELEASE_OUTPUT_STRUCTURAL_PASS_ONLY")
        self.assertEqual(evidence["release"]["member_count"], 12)
        self.assertEqual(evidence["release"]["matching_combination_components"], 8)
        self.assertFalse(evidence["bit_for_bit_reproducibility_verified"])

    def test_changed_source_after_preflight_rejected(self):
        before = provenance.prebuild(self.dir)
        with (self.dir / "build" / "mkrelease.sh").open("ab") as out:
            out.write(b" # modified")
        with self.assertRaisesRegex(SafetyError, "changed since preflight"):
            provenance.finalize(self.dir, before)

    def test_changed_input_after_preflight_rejected(self):
        before = provenance.prebuild(self.dir)
        with (self.images / "vendor.img").open("ab") as out:
            out.write(b"changed")
        with self.assertRaisesRegex(SafetyError, "changed since preflight"):
            provenance.finalize(self.dir, before)

    def test_no_published_tar_rejected_at_finalization(self):
        (self.images / "R800-WearOS.tar.md5").unlink()
        with self.assertRaises((SafetyError, OSError)):
            provenance.finalize(self.dir, provenance.prebuild(self.dir))

    def test_payload_flags_rejected(self):
        for marker in ("DEV", "STAY", "SLEEP", "CPUIDLE_DEEP", "OVERLAY"):
            with self.subTest(marker=marker):
                altered = dict(self.payload_files)
                altered["r800dev/android/" + marker] = b""
                write_tar(self.payload, altered)
                with self.assertRaisesRegex(SafetyError, "Watch-specific"):
                    provenance.validate_payload(self.payload)
        write_tar(self.payload, self.payload_files)

    def test_watch_userdata_rejected(self):
        data = dict(self.payload_files)
        data["r800dev/android/userdata.img"] = b"private"
        write_tar(self.payload, data)
        with self.assertRaises(SafetyError):
            provenance.validate_payload(self.payload)

    def test_persistent_block_must_be_blank(self):
        data = dict(self.payload_files)
        data["r800dev/android/persistent.img"] = b"X" + bytes(1024 * 1024 - 1)
        write_tar(self.payload, data)
        with self.assertRaisesRegex(SafetyError, "nonzero"):
            provenance.validate_payload(self.payload)

    def test_reject_payload_relative_escape(self):
        write_tar(self.payload, self.payload_files,
                  extra_symlink=("r800dev/root/escape", "../../../../etc/shadow"))
        with self.assertRaisesRegex(SafetyError, "Unsafe payload symlink"):
            provenance.validate_payload(self.payload)

    def test_reject_payload_absolute_symlink(self):
        write_tar(self.payload, self.payload_files,
                  extra_symlink=("r800dev/root/escape", "/etc/shadow"))
        with self.assertRaises(SafetyError):
            provenance.validate_payload(self.payload)

    def test_reject_unexpected_tar_root(self):
        data = dict(self.payload_files)
        data["outside/file"] = b"bad"
        write_tar(self.payload, data)
        with self.assertRaisesRegex(SafetyError, "Unexpected payload root"):
            provenance.validate_payload(self.payload)

    def test_reject_combination_cm(self):
        combo = self.images / "samsung" / "COMBINATION-FT40_R800XXU1ARI2_noCM.tar.md5"
        with tarfile.open(combo, "a") as archive:
            member = tarfile.TarInfo("cm.bin")
            member.size = 1
            archive.addfile(member, io.BytesIO(b"x"))
        with self.assertRaisesRegex(SafetyError, "Forbidden"):
            provenance.validate_combination(combo)

    def test_reject_combination_path_escape(self):
        combo = self.images / "samsung" / "COMBINATION-FT40_R800XXU1ARI2_noCM.tar.md5"
        with tarfile.open(combo, "a") as archive:
            member = tarfile.TarInfo("../sboot.bin")
            member.size = 1
            archive.addfile(member, io.BytesIO(b"x"))
        with self.assertRaisesRegex(SafetyError, "Unsafe combination"):
            provenance.validate_combination(combo)

    def test_reject_bad_vendor_filesystem(self):
        (self.images / "vendor.img").write_bytes(bytes(2048))
        with self.assertRaisesRegex(SafetyError, "ext4 magic"):
            provenance.prebuild(self.dir)

    def test_reject_corrupt_boot_nzit(self):
        image = self.images / "boot" / "r800-boot.img"
        data = bytearray(image.read_bytes())
        data[:4] = b"NOPE"
        image.write_bytes(data)
        with self.assertRaisesRegex(SafetyError, "Invalid boot NZIT"):
            provenance.prebuild(self.dir)

    def test_release_script_gates_before_extract(self):
        script = (ROOT / "build" / "mkrelease.sh").read_text(encoding="utf-8")
        self.assertLess(script.index('python3 "$AUDIT" preflight'),
                        script.index('tar -C "$W/combo" -xf'))
        self.assertIn('python3 "$AUDIT" finalize', script)
        self.assertNotIn('[ -f $W/combo/user.img ] || tar', script)
        self.assertLess(script.index('python3 "$AUDIT" finalize'), script.index('mv -- "$PKG"'))
        self.assertIn('e2fsck -fy "$1" || rc=$?', script)
        self.assertNotIn("|| true", script)

    def test_payload_script_delegates_to_curated_builder(self):
        script = (ROOT / "build" / "mkpayload-release.sh").read_text(encoding="utf-8")
        self.assertIn("r800_payload_candidate.py", script)
        self.assertNotIn("cp -a", script)

    def test_additional_debug_flags_rejected(self):
        for marker in ("TZTRACE", "GPU_SCALE", "DIAG", "PANEL_REALBLANK", "ABOX_POWEROFF", "HWC_RESTART"):
            with self.subTest(marker=marker):
                altered = dict(self.payload_files)
                altered["r800dev/android/" + marker] = b""
                write_tar(self.payload, altered)
                with self.assertRaisesRegex(SafetyError, "Watch-specific"):
                    provenance.validate_payload(self.payload)

    def test_finalize_explicit_candidate_without_release_output(self):
        before = provenance.prebuild(self.dir)
        package = self.dir / "candidate.tar.md5"
        shutil.move(str(self.images / "R800-WearOS.tar.md5"), str(package))
        result = provenance.finalize(self.dir, before, package)
        self.assertEqual(result["release"]["name"], package.name)
        self.assertFalse(result["safe_to_flash"])
        self.assertFalse((self.images / "R800-WearOS.tar.md5").exists())

    def test_inventory_includes_additional_vendor_source_file(self):
        extra = self.dir / "src" / "vendor" / "experimental.c"
        extra.parent.mkdir(parents=True, exist_ok=True)
        extra.write_text("int dummy = 1;\n")
        result = provenance.prebuild(self.dir)
        self.assertIn("src/vendor/experimental.c", result["sources"])
        self.assertEqual(result["sources"]["src/vendor/experimental.c"]["size_bytes"], extra.stat().st_size)

    def test_inventory_detects_new_source_added_mid_build(self):
        before = provenance.prebuild(self.dir)
        extra = self.dir / "src" / "hal" / "new_driver.c"
        extra.parent.mkdir(parents=True, exist_ok=True)
        extra.write_text("int new_driver = 1;\n")
        with self.assertRaisesRegex(SafetyError, "changed since preflight"):
            provenance.finalize(self.dir, before)

    def test_missing_closed_vendor_image_refused(self):
        (self.images / "vendor.img").unlink()
        with self.assertRaises(SafetyError):
            provenance.prebuild(self.dir)

    def test_source_symlink_is_refused(self):
        original = self.dir / "src" / "kernel" / "link.c"
        original.parent.mkdir(parents=True, exist_ok=True)
        try:
            original.symlink_to("/etc/passwd")
        except (NotImplementedError, OSError):
            self.skipTest("Fixture platform does not support symlinks")
        with self.assertRaisesRegex(SafetyError, "Symlink in source inventory"):
            provenance.prebuild(self.dir)

    def test_command_line_preflight_and_finalize_create_reports(self):
        from contextlib import redirect_stdout
        output = self.dir / "preflight-evidence.json"
        finished = self.dir / "final-evidence.json"
        with redirect_stdout(io.StringIO()):
            result = provenance.main([
                "preflight", "--release-tree", str(self.dir), "--report", str(output)])
        self.assertEqual(result, 0)
        self.assertTrue(output.exists())
        with redirect_stdout(io.StringIO()):
            result = provenance.main([
                "finalize", "--release-tree", str(self.dir),
                "--input-manifest", str(output), "--report", str(finished)])
        self.assertEqual(result, 0)
        text = finished.read_text(encoding="utf-8")
        self.assertIn('"status": "RELEASE_OUTPUT_STRUCTURAL_PASS_ONLY"', text)
        self.assertIn('"safe_to_flash": false', text)

    def test_command_line_finalize_needs_snapshot(self):
        from contextlib import redirect_stderr
        output = self.dir / "none.json"
        with redirect_stderr(io.StringIO()):
            result = provenance.main([
                "finalize", "--release-tree", str(self.dir),
                "--report", str(output)])
        self.assertEqual(result, 2)
        self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
