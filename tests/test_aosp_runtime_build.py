"""Source build recipe preflight, never sync or build AOSP in unit tests."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "build/r800_aosp_runtime_build.sh"


class AospRuntimeTests(unittest.TestCase):
    def test_shell_syntax(self):
        subprocess.run(["bash", "-n", str(SCRIPT)], check=True)

    def test_missing_arguments(self):
        result = subprocess.run(["bash", str(SCRIPT)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn("usage:", result.stderr)

    def test_invalid_job_count_rejected_before_build(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for jobs in ("0", "100", "4;echo", "-1"):
                result = subprocess.run(["bash", str(SCRIPT), str(root),
                                         str(root / "evidence"), jobs],
                                        capture_output=True, text=True)
                self.assertEqual(result.returncode, 2)
                self.assertIn("Invalid job count", result.stderr)
                self.assertFalse((root / "evidence").exists())

    def test_recipe_pins_manifest_and_target(self):
        source = SCRIPT.read_text()
        self.assertIn("4466d48178452bf5ac136852bf2768af407a0584", source)
        self.assertIn("repo manifest -r", source)
        self.assertIn("lunch aosp_arm64-eng", source)
        self.assertIn('m -j"$JOBS" com.android.runtime', source)
        self.assertIn("r800_android_runtime_extract.py", source)
        self.assertNotIn("fastboot", source)
        self.assertNotIn("gh release", source)


if __name__ == "__main__":
    unittest.main()
