"""Host-source contract for release FD transfer; not sync_file runtime evidence."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class HwcReleaseOwnershipTests(unittest.TestCase):
    def setUp(self):
        source = (ROOT / "src/hal/hwcomposer_r800.c").read_text()
        self.overlay = source.split("static int ovl_present(", 1)[1].split(
            "/* ---- HWC", 1)[0]
        self.enable = source.split("static int ovl_enabled(", 1)[1].split(
            "static int ovl_layer(", 1)[0]

    def test_release_fd_transferred_not_closed(self):
        self.assertIn("l->releaseFenceFd = d.config[w].rel_fence;", self.overlay)
        self.assertIn("d.config[w].rel_fence = -1;", self.overlay)
        self.assertNotIn("close(d.config[w].rel_fence)", self.overlay)

    def test_retire_dup_only_for_missing_release(self):
        self.assertIn("if (l->releaseFenceFd < 0 && d.retire_fence >= 0)", self.overlay)
        self.assertIn("fcntl(d.retire_fence, F_DUPFD_CLOEXEC, 0)", self.overlay)
        self.assertNotIn("dup(d.retire_fence)", self.overlay)
        self.assertIn("*retire = d.retire_fence;", self.overlay)

    def test_missing_fences_disable_future_overlays(self):
        self.assertIn("missing release fence and retire dup failed; disable overlays", self.overlay)
        self.assertIn("missing release and retire fences; disable overlays", self.overlay)
        self.assertGreaterEqual(self.overlay.count("h->ovl_off = 1;"), 3)

    def test_overlays_explicit_opt_in(self):
        self.assertIn('return !strcmp(v, "1");', self.enable)


if __name__ == "__main__":
    unittest.main()
