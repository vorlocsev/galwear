"""Offline Exynos 9110 kernel patch preflight with disposable synthetic git trees.

No network, no source checkout from external repositories, no kernel build and
no changes to an actual kernel tree or watch.
"""
from __future__ import annotations

from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "build"))
import r800_kernel_preflight as gate


def run_git(folder, *args):
    p = subprocess.run(["git", "-C", str(folder), *args],
                       capture_output=True, text=True, check=True)
    return p.stdout.strip()


class StructuralPatchTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)

    def test_repository_patch_and_config_statics(self):
        report = gate.inspect_project(ROOT)
        self.assertEqual(report["status"], "STATIC_ONLY_SOURCE_NOT_PROVIDED")
        self.assertEqual(report["expected_kernel_base"], gate.PINNED_BASE)
        self.assertFalse(report["patch_matches_supplied_kernel_tree"])
        self.assertFalse(report["kernel_compiled"])
        self.assertFalse(report["safe_to_flash"])
        self.assertGreaterEqual(report["static_patch_audit"]["patch_files"], 100)
        self.assertGreaterEqual(report["static_patch_audit"]["patch_hunks"], 100)

    def test_required_exynos_sections_present(self):
        check = gate.inspect_patch(ROOT / "src/kernel/r800-wearos.patch")
        self.assertTrue(check["exynos_power_files_present"])
        self.assertEqual(len(check["patch_sha256"]), 64)

    def test_kernel_config_has_suspend_and_ssp_options(self):
        check = gate.inspect_config(ROOT / "src/kernel/r800.config")
        self.assertTrue(check["required_options_present"])

    def test_missing_patch_rejected(self):
        with self.assertRaises(gate.PreflightError):
            gate.inspect_patch(self.folder / "not-present.patch")

    def test_patch_path_traversal_rejected(self):
        self.assertFalse(gate._safe_patch_path("drivers/../../etc/passwd"))
        self.assertFalse(gate._safe_patch_path("/drivers/a.c"))
        self.assertFalse(gate._safe_patch_path("drivers//a.c"))
        self.assertFalse(gate._safe_patch_path("drivers/./a.c"))

    def test_patch_unapproved_root_rejected(self):
        self.assertFalse(gate._safe_patch_path(".github/workflows/evil.yml"))
        self.assertFalse(gate._safe_patch_path("payload/android-helper.sh"))

    def test_missing_power_config_rejected(self):
        original = (ROOT / "src/kernel/r800.config").read_text()
        altered = original.replace("CONFIG_SUSPEND=y", "# CONFIG_SUSPEND is not set")
        self.assertNotEqual(original, altered)
        file = self.folder / "bad.config"
        file.write_text(altered)
        with self.assertRaisesRegex(gate.PreflightError, "CONFIG_SUSPEND"):
            gate.inspect_config(file)

    def test_missing_project_dt_rejected(self):
        # Test a second synthetic root; never modify real sources.
        tree = self.folder / "repo"
        (tree / "src/kernel").mkdir(parents=True)
        shutil.copy2(ROOT / "src/kernel/r800-wearos.patch",
                     tree / "src/kernel/r800-wearos.patch")
        shutil.copy2(ROOT / "src/kernel/r800.config",
                     tree / "src/kernel/r800.config")
        with self.assertRaises(gate.PreflightError):
            gate.inspect_project(tree)

    def test_cli_generates_static_only_json(self):
        path = self.folder / "kernel-preflight.json"
        with redirect_stdout(io.StringIO()):
            code = gate.main(["--repository", str(ROOT), "--report", str(path)])
        self.assertEqual(code, 0)
        report = json.loads(path.read_text())
        self.assertEqual(report["status"], "STATIC_ONLY_SOURCE_NOT_PROVIDED")
        self.assertFalse(report["safe_to_flash"])

    def test_cli_missing_repo_rejects(self):
        path = self.folder / "failure.json"
        with redirect_stdout(io.StringIO()):
            code = gate.main(["--repository", str(self.folder / "missing"),
                              "--report", str(path)])
        self.assertEqual(code, 2)
        report = json.loads(path.read_text())
        self.assertEqual(report["status"], "REJECT")
        self.assertFalse(report["safe_to_flash"])

    def test_patch_generator_pinned_and_correct_path(self):
        src = (ROOT / "build/mk_kernel_patch.sh").read_text()
        self.assertIn('REPO/src/kernel/r800-wearos.patch', src)
        self.assertNotIn('REPO/kernel/r800-wearos.patch', src)
        self.assertIn('BASE=' + gate.PINNED_BASE, src)


class SyntheticKernelTreeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)
        self.kernel = self.folder / "synthetic-kernel"
        self.kernel.mkdir()
        run_git(self.kernel, "init", "-q")
        run_git(self.kernel, "config", "user.email", "test@example.invalid")
        run_git(self.kernel, "config", "user.name", "Synthetic Test")
        self.file = self.kernel / "drivers/cpuidle/cpuidle-exynos64.c"
        self.file.parent.mkdir(parents=True)
        self.file.write_text("start\n")
        run_git(self.kernel, "add", ".")
        run_git(self.kernel, "commit", "-q", "-m", "synthetic base")
        self.head = run_git(self.kernel, "rev-parse", "HEAD")
        self.file.write_text("start\nchanged\n")
        patch_text = run_git(self.kernel, "diff")
        self.patch = self.folder / "synthetic.patch"
        self.patch.write_text(patch_text + "\n")
        self.file.write_text("start\n")
        self.assertEqual(run_git(self.kernel, "status", "--porcelain"), "")

    def test_valid_pinned_fixture_git_check_no_changes(self):
        before = run_git(self.kernel, "rev-parse", "HEAD")
        result = gate.inspect_tree(
            self.kernel, self.patch, expected_base=before)
        self.assertEqual(result["git_apply_check"], "PASS")
        self.assertFalse(result["kernel_compiled"])
        self.assertFalse(result["source_worktree_modified"])
        self.assertEqual(run_git(self.kernel, "rev-parse", "HEAD"), before)
        self.assertEqual(run_git(self.kernel, "status", "--porcelain"), "")
        self.assertEqual(self.file.read_text(), "start\n")

    def test_wrong_base_rejected_without_patch_application(self):
        with self.assertRaisesRegex(gate.PreflightError, "SHA differs"):
            gate.inspect_tree(self.kernel, self.patch)
        self.assertEqual(self.file.read_text(), "start\n")

    def test_dirty_tree_refused(self):
        self.file.write_text("dirty!\n")
        with self.assertRaisesRegex(gate.PreflightError, "dirty"):
            gate.inspect_tree(
                self.kernel, self.patch, expected_base=self.head)
        self.assertEqual(self.file.read_text(), "dirty!\n")

    def test_bad_patch_context_refused(self):
        self.patch.write_text(
            self.patch.read_text().replace("+changed", "+changed")
            .replace("-start", "-different-start"))
        with self.assertRaisesRegex(gate.PreflightError, "Git apply returned"):
            gate.inspect_tree(
                self.kernel, self.patch, expected_base=self.head)

    def test_no_source_tree_refused(self):
        with self.assertRaisesRegex(gate.PreflightError, "worktree"):
            gate.inspect_tree(self.folder, self.patch,
                              expected_base=self.head)


if __name__ == "__main__":
    unittest.main()
