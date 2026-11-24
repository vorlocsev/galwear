"""Verify the no-plugin close guard in the actual tinyalsa patch."""
from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]
PATCH = ROOT / "build/patches/tinyalsa-2.0.0-sync-ptr.patch"


class TinyalsaLinkTests(unittest.TestCase):
    def test_no_plugin_close_is_preprocessed_out(self):
        patch = PATCH.read_text()
        self.assertIn("+#ifdef TINYALSA_USES_PLUGINS\n     snd_utils_close_dev_node(pcm->snd_node);\n+#endif", patch)
        source = "#ifdef TINYALSA_USES_PLUGINS\nsnd_utils_close_dev_node(pcm->snd_node);\n#endif\n"
        for enabled in (False, True):
            flags = ["cc", "-E", "-P", "-x", "c"]
            if enabled:
                flags.append("-DTINYALSA_USES_PLUGINS")
            result = subprocess.run(flags + ["-"], input=source, text=True,
                                    capture_output=True, check=True, timeout=10)
            self.assertEqual("snd_utils_close_dev_node" in result.stdout, enabled)

    def test_patch_format(self):
        subprocess.run(["git", "apply", "--numstat", str(PATCH)], cwd=ROOT,
                       capture_output=True, check=True, timeout=10)

    def test_direct_hardware_static_build_retains_no_undefined_gate(self):
        source = (ROOT / "build/r800_hal_link_smoke.sh").read_text()
        self.assertIn("git apply --check", source)
        self.assertIn("-Wl,--no-undefined", source)
        self.assertNotIn("-DTINYALSA_USES_PLUGINS", source)


if __name__ == "__main__":
    unittest.main()
