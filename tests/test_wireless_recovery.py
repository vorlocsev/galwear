"""Host-only checks for developer Wi-Fi configuration and ownership guards."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "payload/android-helper.sh"


class WirelessRecoveryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = SOURCE.read_text()

    def ssid(self, config):
        line = next(x.strip() for x in self.source.splitlines() if x.strip().startswith("SSID="))
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "wpa.conf"
            path.write_text(config)
            script = "B=\n" + line.replace("/oem/r800dev/wpa.conf", str(path)) + '\nprintf "%s" "$SSID"'
            result = subprocess.run(["sh", "-eu"], input=script, text=True,
                                    capture_output=True, check=True, timeout=5)
            return result.stdout

    def test_ssid_extraction(self):
        self.assertEqual(self.ssid('network={\n    ssid="Test Network"\n}\n'), "Test Network")

    def test_first_ssid(self):
        self.assertEqual(self.ssid('ssid="First"\nssid="Second"\n'), "First")

    def test_missing_ssid(self):
        self.assertEqual(self.ssid("network={}\n"), "")

    def test_no_corrupted_backreference(self):
        self.assertNotIn(chr(1), self.source)

    def test_fallback_requires_stopped_android_supplicant(self):
        self.assertIn('getprop init.svc.wpa_supplicant)" = stopped', self.source)
        self.assertIn('getprop init.svc.wpa_supplicant)" != stopped', self.source)

    def test_no_background_daemon_spawn_per_retry(self):
        self.assertIn('kill -0 "$wpa_pid"', self.source)
        self.assertIn('kill -0 "$dhcp_pid"', self.source)
        self.assertIn('udhcpc -f -i wlan0', self.source)
        self.assertNotIn('udhcpc -i wlan0 -s $W/dhcp.sh -b', self.source)

    def test_keepwifi_only_in_android_mode(self):
        self.assertEqual(self.source.count('[ "$MODE" = android ] && [ -f /oem/r800dev/keepwifi.dex ]'), 2)

    def test_private_configuration(self):
        self.assertIn('chmod 700 "$W"', self.source)
        self.assertIn('chmod 600 "$W/wpa.conf"', self.source)

    def test_shell_syntax(self):
        subprocess.run(["sh", "-n", str(SOURCE)], check=True, timeout=5)


if __name__ == "__main__":
    unittest.main()
