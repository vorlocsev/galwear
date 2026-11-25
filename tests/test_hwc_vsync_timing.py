"""Compile and exercise production VSync arithmetic on the host; no device I/O."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src/hal/hwcomposer_r800.c"


class VsyncTimingTests(unittest.TestCase):
    def test_production_timing_functions(self):
        source = SOURCE.read_text()
        parse = source[source.index("static int64_t parse_hw_vsync("):
                       source.index("static int64_t read_hw_vsync(")]
        timer = source[source.index("static int64_t next_timer_vsync("):
                       source.index("static void *vsync_loop(")]
        period = next(line for line in source.splitlines()
                      if line.startswith("#define VSYNC_PERIOD_NS "))
        harness = """
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
""" + period + "\n" + parse + timer + r"""
int main(void) {
    const int64_t now = 5000000000LL;
    assert(parse_hw_vsync("4999999999\n", now) == 4999999999LL);
    const char *bad[] = {"", "-1", " 1", "0", "5000000001",
                         "2999999999", "4999999999junk",
                         "999999999999999999999999999999"};
    for (unsigned i = 0; i < sizeof(bad)/sizeof(bad[0]); i++)
        assert(parse_hw_vsync(bad[i], now) == 0);
    assert(next_timer_vsync(now, 0, 0) == now + VSYNC_PERIOD_NS);
    assert(next_timer_vsync(now, now + 1, 0) == now + VSYNC_PERIOD_NS);
    assert(next_timer_vsync(now, 1, 0) == now + VSYNC_PERIOD_NS);
    for (int64_t offset = 0; offset < VSYNC_PERIOD_NS; offset += 100003) {
        int64_t base = now - offset;
        int64_t next = next_timer_vsync(now, base, now - 1);
        assert(next > now);
        assert(next > now - 1 + VSYNC_PERIOD_NS / 2);
        assert(next <= now + 2 * VSYNC_PERIOD_NS);
        assert((next - base) % VSYNC_PERIOD_NS == 0);
    }
    return 0;
}
"""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "vsync.c"
            exe = Path(tmp) / "vsync"
            path.write_text(harness)
            build = subprocess.run(["cc", "-std=c99", "-Wall", "-Wextra", "-Werror",
                                    str(path), "-o", str(exe)],
                                   capture_output=True, text=True, timeout=15)
            self.assertEqual(build.returncode, 0, build.stderr)
            subprocess.run([str(exe)], check=True, timeout=5)

    def test_poll_errors_have_timer_fallback(self):
        source = SOURCE.read_text()
        loop = source[source.index("static void *vsync_loop("):
                      source.index("static int r800_event_control(")]
        self.assertIn("p.revents & POLLPRI", loop)
        self.assertIn("POLLHUP | POLLNVAL", loop)
        self.assertIn("next_timer_vsync(now, last_hw, last_sent)", loop)
        self.assertNotIn("else\n\t\t\t\t\tcontinue;", loop)
        self.assertIn("while (rc == EINTR)", loop)

    def test_enable_epoch_and_callback_snapshot(self):
        source = SOURCE.read_text()
        self.assertIn("h->vsync_epoch++", source)
        self.assertIn("h->vsync_epoch == epoch", source)
        self.assertIn("procs = h->procs;", source)
        self.assertIn("ts > last_sent", source)


if __name__ == "__main__":
    unittest.main()
