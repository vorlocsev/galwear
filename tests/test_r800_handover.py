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

    def test_binder_gate_before_switch_root(self):
        source = SCRIPT.read_text()
        handover = source.index("exec $B switch_root /newroot /init")
        for needle in ('for DEVICE in binder hwbinder vndbinder',
                       'test -c "/dev/$DEVICE"', 'system/bin/servicemanager',
                       'vendor/bin/vndservicemanager', 'test -x /newroot/system/bin/app_process32'):
            self.assertLess(source.index(needle), handover)

    def test_boot_observation_is_bounded_and_read_only(self):
        helper = ROOT / "payload/android-helper.sh"
        source = helper.read_text()
        start = source.index("boot_observe() {")
        end = source.index("\n}", start) + 2
        body = source[start:end]
        self.assertIn("seq 1 120", body)
        self.assertIn("sleep 2", body)
        self.assertIn("sys.boot_completed", body)
        self.assertIn("pidof system_server", body)
        self.assertNotIn("setprop", body)
        self.assertNotIn("ctl.start", body)
        result = subprocess.run(["sh", "-n", str(helper)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_radio_bind_before_android_handover(self):
        source = SCRIPT.read_text()
        handover = source.index("exec $B switch_root /newroot /init")
        for needle in ('android_require "radio firmware bind"',
                       'android_require "Broadcom vendor library bind"',
                       'bcmdhd_sta.bin', 'nvram_net.txt', 'bcmdhd_clm.blob'):
            self.assertLess(source.index(needle), handover)
        helper = (ROOT / "payload/android-helper.sh").read_text()
        self.assertNotIn("mount --bind $BT/libbt-vendor.so", helper)
        self.assertNotIn("mount --bind /oem/r800dev/fw /vendor/data/r800dev/fw", helper)

    def test_no_unauthenticated_network_shell(self):
        for path in (SCRIPT, ROOT / "payload/android-helper.sh"):
            source = path.read_text()
            self.assertNotIn("busybox-extras", source)
            self.assertNotIn("telnetd", source)
            self.assertNotIn("tnet()", source)
            self.assertNotIn("telnet on 23", source)
        candidate = (ROOT / "build/r800_payload_candidate.py").read_text()
        self.assertNotIn('"busybox-extras"', candidate)

    def test_wifi_uses_staged_static_binary(self):
        source = (ROOT / "payload/android-helper.sh").read_text()
        self.assertIn("WPA=/oem/r800dev/bin/wpa_supplicant", source)
        self.assertIn('if [ "$(/system/bin/getprop init.svc.wpa_supplicant)" = stopped ]; then', source)
        self.assertIn('"$WPA" -i wlan0 -D nl80211', source)
        self.assertNotIn("ld-musl-aarch64.so.1", source)

    def test_existing_display_and_wifi_guards_retained(self):
        source = (ROOT / "payload/android-helper.sh").read_text()
        for marker in ("PANEL_REALBLANK", "r800-display-watchdog.sh",
                       "wifi fallback aborted: config preparation failed"):
            self.assertIn(marker, source)

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
