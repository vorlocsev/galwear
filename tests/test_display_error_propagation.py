"""Source regressions for DSIM and DECON error propagation."""
from pathlib import Path
import unittest

PATCH = Path(__file__).resolve().parents[1] / "src/kernel/r800-wearos.patch"


def postimage(patch, name):
    section = patch.split(f"diff --git a/{name} b/{name}\n", 1)[1].split("\ndiff --git ", 1)[0]
    return "\n".join(x[1:] for x in section.splitlines()
                     if x.startswith((" ", "+")) and not x.startswith("+++"))


class DisplayErrorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        patch = PATCH.read_text(encoding="utf-8")
        cls.dsim = postimage(patch, "drivers/video/fbdev/exynos/dpu30/dsim_drv.c")
        cls.decon = postimage(patch, "drivers/video/fbdev/exynos/dpu30/decon_core.c")

    def test_bounded_fifo_waits(self):
        self.assertIn("for (cnt = 5000; cnt > 0; cnt--)", self.dsim)
        self.assertIn("for (; cnt > 0; cnt--)", self.dsim)
        self.assertIn("ret = -ETIMEDOUT;", self.dsim)

    def test_dcs_on_off_wait_for_fifo(self):
        self.assertIn("MIPI_DCS_SET_DISPLAY_ON, 0, true);", self.dsim)
        self.assertIn("MIPI_DCS_SET_DISPLAY_OFF, 0, true);", self.dsim)

    def test_read_command_error(self):
        self.assertIn("ret = dsim_wait_for_cmd_done(dsim);\n\tif (ret < 0)\n\t\tgoto unblock;", self.dsim)

    def test_timeout_balances_hibernation(self):
        self.assertIn("ret = -ETIMEDOUT;\n\t\tgoto unblock;", self.dsim)
        self.assertIn("unblock:\n\tdecon_hiber_unblock(decon);", self.dsim)

    def test_rx_length_checks(self):
        for guard in ("if (rx_size > cnt)", "if (cnt < 2)", "if (!buf || !cnt)"):
            self.assertIn(guard, self.dsim)

    def test_unblank_returns_synchronous_result(self):
        self.assertIn("ret = r800_decon_displayon_checked(decon);", self.decon)
        self.assertIn("return ret;\n}\n\nstatic void decon_displayon(", self.decon)

    def test_invalid_and_denied_blank_are_errors(self):
        self.assertIn('decon_info("r800: POWERDOWN denied, panel kept on\\n");\n\t\t\tret = -EOPNOTSUPP;', self.decon)
        self.assertIn('decon_info("Display invalid, not processing blank event\\n");\n\t\treturn -ENODEV;', self.decon)

    def test_interrupted_vsync_propagated(self):
        self.assertIn("if (ret < 0)\n\t\treturn ret;\n\tif (timeout && ret == 0)", self.decon)


if __name__ == "__main__":
    unittest.main()
