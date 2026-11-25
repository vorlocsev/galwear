"""Run actual display and ABOX policy snippets against synthetic files."""
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "payload/android-helper.sh"
PACK = ROOT / "build/mkpayload-release.sh"


class DisplayPowerTests(unittest.TestCase):
    def simulate(self, boot, panel=False, abox=False, control="auto",
                 missing_param=False, reject_property=False):
        script = HELPER.read_text()
        blocks = []
        for start_marker, end_marker in (
            ("    # Real blank requires both", "    # END DISPLAY POWER POLICY"),
            ("    # ABOX POWER POLICY:", "    # END ABOX POWER POLICY"),
        ):
            start = script.index(start_marker)
            blocks.append(script[start:script.index(end_marker, start)])
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "control").write_text(control + "\n")
            (root / "keep").write_text("9\n")
            (root / "property").write_text("9\n")
            param = root / "abox"
            if missing_param:
                param.mkdir()
            else:
                param.write_text("0\n")
            if panel:
                (root / "PANEL_REALBLANK").touch()
            if abox:
                (root / "ABOX_POWEROFF").touch()
            snippet = "\n".join(blocks)
            for src, dst in {
                "/system/bin/getprop": "getprop",
                "/system/bin/setprop": "setprop",
                "/oem/r800dev/android/": str(root) + "/",
                "/sys/module/decon/parameters/r800_keep_panel_on": str(root / "keep"),
                "/sys/devices/platform/14a50000.abox/power": str(root),
                "/sys/module/abox/parameters/r800_rtpm_poweroff": str(param),
            }.items():
                snippet = snippet.replace(src, dst)
            for unsafe in ("/sys/", "/oem/", "/system/bin/"):
                self.assertNotIn(unsafe, snippet)
            prefix = (
                "B=; k() { :; }; sleep() { :; }\n"
                f"PROP={shlex.quote(str(root / 'property'))}\n"
                f"BOOT={int(boot)}; REJECT={int(reject_property)}\n"
                'getprop() { case "$1" in sys.boot_completed) echo "$BOOT";; '
                'debug.r800.realblank) cat "$PROP";; *) return 1;; esac; }\n'
                'setprop() { [ "$1" = debug.r800.realblank ] || return 1; '
                'if [ "$REJECT" = 1 ] && [ "$2" = 1 ]; then return 1; fi; '
                'printf "%s\\n" "$2" > "$PROP"; }\n'
            )
            result = subprocess.run(["sh", "-eu"], input=prefix + snippet + "\nwait\n",
                                    capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual((root / "property").read_text().strip(),
                             "1" if boot and panel and not reject_property else "0")
            return ((root / "keep").read_text().strip(),
                    None if missing_param else param.read_text().strip(),
                    (root / "control").read_text().strip())

    def test_incomplete_boot_resets_panel_and_denies_opt_ins(self):
        self.assertEqual(self.simulate(False, True, True), ("1", "0", "auto"))

    def test_default_keep_panel_on_and_no_abox_cycle(self):
        self.assertEqual(self.simulate(True), ("1", "0", "auto"))

    def test_independent_panel_opt_in(self):
        self.assertEqual(self.simulate(True, True, False), ("0", "0", "auto"))

    def test_independent_abox_opt_in(self):
        self.assertEqual(self.simulate(True, False, True), ("1", "1", "auto"))

    def test_panel_property_failure_rolls_back_kernel_gate(self):
        self.assertEqual(self.simulate(True, True, False, reject_property=True),
                         ("1", "0", "auto"))

    def test_abox_original_on_is_preserved(self):
        self.assertEqual(self.simulate(True, False, True, control="on"), ("1", "1", "on"))

    def test_abox_unknown_control_rejected(self):
        self.assertEqual(self.simulate(True, False, True, control="invalid"), ("1", "0", "invalid"))

    def test_abox_parameter_error_restores_control(self):
        self.assertEqual(self.simulate(True, False, True, missing_param=True), ("1", None, "auto"))

    def test_packaging_strips_experiments(self):
        line = next(x for x in PACK.read_text().splitlines() if x.startswith("for marker in "))
        for marker in ("PANEL_REALBLANK", "ABOX_POWEROFF", "GPU_SCALE", "SLEEP", "CPUIDLE_DEEP"):
            self.assertIn(marker, line.split())

    def test_shell_syntax(self):
        for path in (HELPER, PACK):
            subprocess.run(["sh", "-n", str(path)], check=True, timeout=5)


if __name__ == "__main__":
    unittest.main()
