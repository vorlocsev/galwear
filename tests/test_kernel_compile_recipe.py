"""Offline checks for disposable SM-R800 kernel Image compile recipe.

Never clones external repositories or invokes a kernel compiler.
"""
from __future__ import annotations

from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "build/r800_kernel_compile_smoke.sh"


class CompileRecipeTests(unittest.TestCase):
    def test_shell_syntax(self):
        p = subprocess.run(["sh", "-n", str(SCRIPT)],
                           capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stderr)

    def test_exact_base_pinned(self):
        s = SCRIPT.read_text()
        self.assertIn("BASE=50db73fc799f20a7120a8b5f653b16cc123d856f", s)
        self.assertIn('git -C "$SOURCE" rev-parse HEAD', s)

    def test_llvm_exact_patch_version_required(self):
        s = SCRIPT.read_text()
        self.assertIn("clang-19 --version", s)
        self.assertIn("ld.lld --version", s)
        self.assertIn("19\\.1\\.4", s)
        self.assertIn("CC=clang-19", s)

    def test_initramfs_override_only_in_out_config(self):
        s = SCRIPT.read_text()
        self.assertIn('cp "$REPO/src/kernel/r800.config" "$OUT/.config"', s)
        self.assertIn('p = Path(sys.argv[1])', s)
        self.assertIn('CONFIG_INITRAMFS_SOURCE=""', s)
        self.assertIn('make -C "$SOURCE" O="$OUT" olddefconfig', s)

    def test_no_flash_or_release_publishing(self):
        s = SCRIPT.read_text()
        for command in ("git push", "gh release", "odin --", "netodin.py",
                        "fastboot flash", "adb shell"):
            self.assertNotIn(command, s)

    def test_expects_disposable_source_and_output(self):
        s = SCRIPT.read_text()
        self.assertIn('git -C "$SOURCE" apply --check', s)
        self.assertIn('git -C "$SOURCE" apply "$REPO/src/kernel/r800-wearos.patch"', s)
        self.assertIn('[ ! -e "$OUT" ]', s)

    def test_dt_bindings_header_changes_symlink_to_regular_file(self):
        patch = (ROOT / "src/kernel/r800-wearos.patch").read_text()
        header = (
            "diff --git a/include/dt-bindings/input/linux-event-codes.h "
            "b/include/dt-bindings/input/linux-event-codes.h"
        )
        section = patch.split(header, 1)[1].split("diff --git ", 1)[0]
        self.assertIn("old mode 120000", section)
        self.assertIn("new mode 100644", section)
        self.assertNotIn("index 693bbcd26..5bef201e9 120000", section)
        self.assertIn("+/* SPDX-License-Identifier", section)

    def test_no_arguments_does_not_create_files(self):
        result = subprocess.run(["sh", str(SCRIPT)],
                                capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 2)
        self.assertIn("usage:", result.stderr)


if __name__ == "__main__":
    unittest.main()
