"""Host stub tests of failure collection; never claim a real NDK build."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "build/r800_hal_compile_smoke.sh"
MODULES = {"audio_r800", "gps_r800", "sensors_r800", "hwcomposer_r800"}


class HalCompileDiagnosticsTests(unittest.TestCase):
    def simulate_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            ndk = base / "ndk"
            bin = ndk / "toolchains/llvm/prebuilt/linux-x86_64/bin"
            bin.mkdir(parents=True)
            (ndk / "source.properties").write_text("Pkg.Revision = 27.2.12479018\n")
            tiny = base / "tinyalsa"
            tiny.mkdir()
            stubs = base / "bin"
            stubs.mkdir()
            def executable(path, source):
                path.write_text(source)
                path.chmod(0o755)
            executable(stubs / "git", """#!/bin/sh
case "$3" in
rev-parse)
    case "$2" in
    */tinyalsa) echo 1c5fb68ced57d838f2b7ecd0c00bc1fefc9ab60d ;;
    *) echo aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa ;;
    esac ;;
status) exit 0 ;;
*) exit 2 ;;
esac
""")
            executable(bin / "armv7a-linux-androideabi28-clang", """#!/bin/sh
case "$*" in
*gps_r800.c*) echo 'fixture compiler error' >&2; exit 7 ;;
esac
while [ "$#" -gt 0 ]; do
    if [ "$1" = -o ]; then shift; printf fixture > "$1"; exit 0; fi
    shift
done
exit 2
""")
            executable(bin / "llvm-readelf", "#!/bin/sh\necho 'Machine: ARM'\n")
            out = base / "out"
            env = dict(os.environ, PATH=str(stubs) + os.pathsep + os.environ["PATH"],
                       GITHUB_RUN_ID="123", GITHUB_RUN_ATTEMPT="1")
            result = subprocess.run(["sh", str(SCRIPT), str(ROOT), str(ndk), str(tiny), str(out)],
                                    env=env, capture_output=True, text=True, timeout=15)
            report = json.loads((out / "hal-compile-diagnostics.json").read_text())
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((out / "hal-compile.json").exists())
            return report

    def test_all_modules_attempted_despite_failure(self):
        report = self.simulate_failure()
        self.assertEqual(set(report["modules"]), MODULES)
        self.assertFalse(report["all_compiled"])
        self.assertFalse(report["safe_to_flash"])
        self.assertEqual(report["modules"]["gps_r800"]["exit_code"], 7)
        self.assertTrue(report["modules"]["hwcomposer_r800"]["compiled_and_arm_header_checked"])

    def test_failure_retains_bounded_diagnostic_and_identity(self):
        report = self.simulate_failure()
        self.assertIn("fixture compiler error", report["modules"]["gps_r800"]["diagnostics"])
        self.assertEqual(report["run_id"], "123")
        self.assertEqual(report["run_attempt"], "1")

    def test_overlay_marker_explicitly_sets_both_modes(self):
        source = (ROOT / "payload/android-helper.sh").read_text()
        self.assertIn('if [ -f /oem/r800dev/android/OVERLAY ]; then\n    /system/bin/setprop vendor.hwc.r800.overlay 1\nelse\n    /system/bin/setprop vendor.hwc.r800.overlay 0\nfi', source)


if __name__ == "__main__":
    unittest.main()
