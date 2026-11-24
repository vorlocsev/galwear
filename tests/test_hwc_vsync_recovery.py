"""Host fixture of actual VSync parsing, freshness and deadline arithmetic."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class HwcVsyncRecoveryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = (ROOT / "src/hal/hwcomposer_r800.c").read_text()
        s = cls.source
        parse = s[s.index("static int64_t parse_vsync("):s.index("static int64_t read_hw_vsync(")]
        timing = s[s.index("static int fresh_vsync("):s.index("static void *vsync_loop(")]
        harness = r'''
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#define VSYNC_PERIOD_NS 16666667LL
#define VSYNC_MAX_AGE_NS (3 * VSYNC_PERIOD_NS)
''' + parse + timing + r'''
int main(void) {
    const int64_t p=VSYNC_PERIOD_NS, now=100*p;
    assert(parse_vsync("123456789\n")==123456789);
    assert(parse_vsync("123456789")==123456789);
    assert(!parse_vsync("0") && !parse_vsync("-1"));
    assert(!parse_vsync(" 123") && !parse_vsync("123 junk"));
    assert(!parse_vsync("9223372036854775808"));
    assert(fresh_vsync(now,now) && fresh_vsync(now-3*p,now));
    assert(!fresh_vsync(now+1,now) && !fresh_vsync(now-3*p-1,now));
    assert(next_vsync(now,0,0)==now);
    assert(next_vsync(now,now-p,now)==now+p);
    assert(next_vsync(now+1,now-p,now)==now+p);
    assert(next_vsync(now,now-90*p,now-90*p)==now);
    assert(next_vsync(now,now+1,now-p)==now);
    for(int i=0;i<1000;i++){
        int64_t t=now+i*1234567, prev=t-p/2;
        int64_t next=next_vsync(t,now-p,prev);
        assert(next>=t && next<=t+p && next>prev);
    }
    return 0;
}
'''
        cls.tmp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.tmp.cleanup)
        src = Path(cls.tmp.name) / "vsync.c"
        cls.exe = Path(cls.tmp.name) / "vsync"
        src.write_text(harness)
        subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                        str(src), "-o", str(cls.exe)], check=True, timeout=15)

    def test_actual_timing_helpers(self):
        subprocess.run([str(self.exe)], check=True, timeout=5)

    def test_poll_uses_precomputed_timer_deadline(self):
        self.assertIn("target = next_vsync(now, last_hw, last_sent)", self.source)
        self.assertIn("target - now + 999999", self.source)
        self.assertIn("ts = now - (now - target) % VSYNC_PERIOD_NS", self.source)

    def test_duplicate_te_cannot_skip_fallback(self):
        s = self.source.split("if (pr > 0)",1)[1].split("if (!ts)",1)[0]
        self.assertNotIn("continue;", s)
        self.assertIn("++bad >= VSYNC_BAD_LIMIT", s)

    def test_sysfs_error_pair_and_reopen(self):
        self.assertIn("p.revents & (POLLPRI | POLLERR)", self.source)
        self.assertIn("p.revents & (POLLHUP | POLLNVAL)", self.source)
        self.assertIn("reopen_at = mono_ns() + VSYNC_REOPEN_NS", self.source)
        self.assertIn("mono_ns() - last_valid_at >= VSYNC_SILENT_NS", self.source)

    def test_callback_monotonic_and_worker_stoppable(self):
        self.assertIn("if (ts <= last_sent)", self.source)
        self.assertIn("while (rc == EINTR && !atomic_load(&h->stopping))", self.source)
        self.assertIn("while (!h->vsync_enabled && !atomic_load(&h->stopping))", self.source)


if __name__ == "__main__":
    unittest.main()
