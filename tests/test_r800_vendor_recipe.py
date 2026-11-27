"""Offline vendor/release recipe guards; no loop mounts, root operations or device access."""
from pathlib import Path
import subprocess
import unittest
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "build/build_vendor.sh"


class VendorRecipeTests(unittest.TestCase):
    def setUp(self):
        self.source = SCRIPT.read_text()

    def test_shell_syntax(self):
        subprocess.run(["bash", "-n", str(SCRIPT)], check=True)
        for name in ("mkpayload-release.sh", "mkrelease.sh"):
            subprocess.run(["sh", "-n", str(ROOT / "build" / name)], check=True)

    def test_donors_read_only_and_checked_before_mount(self):
        gate = self.source.index('r800_vendor_inputs.py')
        for label in ("SRC", "J4"):
            command = 'mount -t ext4 -o loop,ro,noload,nodev,nosuid,noexec "$' + label + '"'
            self.assertLess(gate, self.source.index(command))
        self.assertIn("trap cleanup EXIT", self.source)
        self.assertNotIn("/mnt/d/", self.source)

    def test_manifest_groups_have_required_donor_checks(self):
        root = ET.parse(ROOT / "src/vendor/etc/vintf/manifest.xml").getroot()
        names = {node.findtext("name") for node in root.findall("hal")}
        for name in ("sensors", "gnss", "wifi", "wifi.supplicant"):
            self.assertIn("android.hardware." + name, names)
        for group in ("sensors", "gnss", "wifi"):
            self.assertIn("copy_hidl_group " + group, self.source)
        self.assertIn("Missing complete HIDL 1.0 donor group", self.source)

    def test_publish_only_after_offline_checks(self):
        final = self.source.index('mv -- "$IMAGE" "$WORK/vendor.candidate.img"')
        for gate in ('e2fsck -fn "$IMAGE"',
                     'cmp "$WORK/input-evidence.json" "$WORK/input-evidence-after.json"',
                     'umount "$J4_MNT"', 'umount "$BASE_MNT"'):
            self.assertLess(self.source.index(gate), final)
        self.assertIn("safe_to_flash=false", self.source)

    def test_existing_workspace_rejected(self):
        result = subprocess.run(
            ["bash", str(SCRIPT), *([str(ROOT)] * 5)],
            capture_output=True, text=True, timeout=5)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("work directory must not exist", result.stderr)


if __name__ == "__main__":
    unittest.main()
