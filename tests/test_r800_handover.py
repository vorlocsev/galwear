"""Offline tests of required-command gate; never execute start.sh on host."""
from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "payload/start.sh"


class HandoverTests(unittest.TestCase):
    def test_shell_syntax(self):
        result = subprocess.run(["sh", "-n", str(SCRIPT)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_required_command_success(self):
        result = self.run_gate("true")
        self.assertEqual(result.returncode, 0)
        self.assertIn("system mount OK", result.stdout)
        self.assertIn("continued", result.stdout)

    def test_required_command_failure(self):
        result = self.run_gate("false")
        self.assertEqual(result.returncode, 42)
        self.assertIn("blocked system mount", result.stdout)
        self.assertNotIn("continued", result.stdout)
        self.assertNotIn("system mount OK", result.stdout)

    def run_gate(self, command):
        source = SCRIPT.read_text()
        start = source.index("android_require() {")
        end = source.index("\n}", start) + 2
        # Execute only the small gate with harmless commands and stubbed logging.
        fixture = (
            'log() { printf "%s\\n" "$*"; }\n'
            'android_abort() { printf "blocked %s\\n" "$*"; exit 42; }\n'
            + source[start:end] + '\nandroid_require "system mount" ' + command +
            '\nprintf "continued\\n"\n'
        )
        return subprocess.run(["sh", "-c", fixture], capture_output=True, text=True, timeout=5)

    def test_critical_gates_present_before_handover(self):
        source = SCRIPT.read_text()
        start = source.index("if [ -f /data/r800dev/android/BOOT_ANDROID ]; then")
        end = source.index("exec $B switch_root /newroot /init", start)
        body = source[start:end]
        for gate in ("p17 remount", "system mount", "vendor mount",
                     "p17 bind to oem", "data p18 loop attach",
                     "userdata loop attach", "zram loop attach", "guest dev mount"):
            with self.subTest(gate=gate):
                self.assertIn('android_require "' + gate + '"', body)
        self.assertIn('android_abort "data loop lacks ext4 magic"', body)
        self.assertIn('android_abort "unknown Android SDK"', body)
        self.assertIn('android_abort "switch_root returned"', source[end:])


if __name__ == "__main__":
    unittest.main()
