"""Offline build-script syntax and evidence contract checks."""
from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "build/r800_hal_compile_smoke.sh"


class HalCompileScriptTests(unittest.TestCase):
    def test_shell_and_embedded_python_syntax(self):
        subprocess.run(["sh", "-n", str(SCRIPT)], check=True, timeout=5)
        text = SCRIPT.read_text()
        self.assertEqual(text.count("<<'PY'"), 1)
        start = text.index("<<'PY'") + len("<<'PY'\n")
        end = text.index("\nPY\n", start)
        compile(text[start:end], str(SCRIPT), "exec")

    def test_hwc_evidence_requires_link_and_symbol_checks(self):
        text = SCRIPT.read_text()
        evidence = text.index("python3 - ")
        for check in ("--no-undefined", "HMI$", "$module-dynamic.txt", "Type:[[:space:]]+DYN", "ELF32"):
            self.assertIn(check, text[:evidence])
        self.assertIn('"hwc_shared_library_linked": True', text[evidence:])
        self.assertIn('"safe_to_flash": False', text[evidence:])
        self.assertEqual(text.count("galwear-r800-hal-compile-v4"), 1)
        self.assertNotIn("galwear-r800-hal-compile-v1", text)

    def test_all_ndk_only_hal_modules_linked_and_audio_blocked(self):
        text = SCRIPT.read_text()
        self.assertIn("for module in hwcomposer gps sensors lights; do", text)
        self.assertIn("audio_r800 gps_r800 sensors_r800 hwcomposer_r800 lights_r800", text)
        self.assertIn('"audio_linked": False', text)
        self.assertIn('"linked_libraries": libraries', text)
        self.assertIn("unexpected dependencies:", text)
        self.assertIn("actual_soname != [soname]", text)


    def test_audio_candidate_abi_evidence_is_not_hardware_acceptance(self):
        text = SCRIPT.read_text()
        self.assertIn('r800_pcm_abi_probe.c', text)
        self.assertIn('llvm-objcopy', text)
        self.assertIn('struct.unpack("<" + "I" * len(abi_keys)', text)
        self.assertIn('"kernel_compat_abi_verified": False', text)
        self.assertIn('"hardware_validated": False', text)
        self.assertIn("unexpected Audio dependencies:", text)
        self.assertIn('"audio_candidate_linked": True', text)
        self.assertIn('"shared_libraries_linked": True', text)


if __name__ == "__main__":
    unittest.main()
