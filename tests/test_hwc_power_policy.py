"""Static HWC power policy regressions, no hardware access."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class HwcPowerPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.hwc = (ROOT / "src/hal/hwcomposer_r800.c").read_text()
        cls.helper = (ROOT / "payload/android-helper.sh").read_text()

    def test_real_blank_explicit(self):
        self.assertIn('if (h->real_blanked || (blank && !strcmp(v, "1")))', self.hwc)

    def test_dcs_short_write_error(self):
        self.assertIn("ret = written == 1 ? 0 : (written < 0 ? -errno : -EIO);", self.hwc)

    def test_mode_committed_only_after_success(self):
        self.assertIn("if (r)\n\t\tgoto failed;\n\th->doze_susp = suspended;", self.hwc)

    def test_frame_submission_blocked_on_unknown_or_suspended(self):
        self.assertIn("present_ok = !power_ret && !h->blanked && !h->power_unknown && !h->doze_susp;", self.hwc)

    def test_automatic_doze_suspend_default_off(self):
        self.assertIn("if (!v[0])\n\t\treturn 0;\n\tms = strtol", self.hwc)

    def test_monotonic_condition_clock(self):
        self.assertIn("pthread_condattr_setclock(&doze_attr, CLOCK_MONOTONIC);", self.hwc)

    def test_only_successful_frame_updates_idle_timer(self):
        self.assertIn("if (presented) {\n\t\th->last_present_ns = mono_ns();", self.hwc)
        self.assertIn("static int fb_present(", self.hwc)

    def test_helper_confirms_kernel_before_hwc_optin(self):
        self.assertIn('[ "$($B cat "$PANEL_GATE" 2>/dev/null)" = 0 ]', self.helper)
        self.assertIn("setprop debug.r800.realblank 1", self.helper)


if __name__ == "__main__":
    unittest.main()
