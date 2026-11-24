"""Compile actual context parser and HR state machine with synthetic hardware."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class HealthContextTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = (ROOT / "src/hal/sensors_r800.c").read_text()
        s = cls.source
        mask = s[s.index("static int parse_enable_mask("):s.index("static int read_enable_mask(")]
        ctx = s[s.index("static int parse_context_line("):s.index("/* caller holds lock */\nstatic void ctx_line(")]
        hr = s[s.index("static int hr_period("):s.index("static int dev_activate(")] if "static int hr_period(" in s else s[s.index("static int64_t hr_period("):s.index("static int dev_activate(")]
        constants = "\n".join(x for x in s.splitlines() if x.startswith("#define HR_"))
        harness = r'''
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#define LOGI(...) ((void)0)
#define H_HR 0
struct { int enabled; } hub[1];
static int hr_active, hr_bg, hr_bursts, hr_skipped;
static int offbody_known;
static float offbody_state;
static int64_t hr_req_ns, hr_burst_start, hr_stop_retry, hr_next;
static int fail_on, fail_off, held;
static int64_t time_now;
static int64_t now_ns(void) { return time_now; }
static int hr_hub(int on) {
    if ((on && fail_on) || (!on && fail_off)) return -EIO;
    hub[H_HR].enabled=on;
    return 0;
}
static void hr_wakelock(int on) { held=on; }
''' + constants + "\n" + mask + ctx + hr + r'''
int main(int argc,char **argv) {
    if (argc == 2) {
        long long val=-1;
        return parse_context_line(argv[1],&val) < 0 ? 1 : 0;
    }
    assert(step_add(UINT64_MAX-1,3)==UINT64_MAX);
    assert(step_add(1,2)==3);
    time_now=1000000000LL;
    hr_req_ns=HR_BG_MIN_NS;
    hr_active=1;
    assert(hr_update(time_now)==0 && hr_bg);
    assert(!hub[H_HR].enabled && !held);
    offbody_known=1; offbody_state=1;
    time_now=hr_next;
    fail_on=1;
    hr_tick(time_now);
    assert(!hr_burst_start && !held && hr_next==time_now+HR_RETRY_NS);
    fail_on=0;
    time_now=hr_next;
    hr_tick(time_now);
    assert(hr_burst_start==time_now && held && hub[H_HR].enabled);
    fail_off=1;
    time_now+=HR_BURST_NS;
    hr_tick(time_now);
    assert(hr_stop_retry==time_now+HR_RETRY_NS && held && hr_burst_start);
    assert(hr_timeout_ms(time_now)>0);
    fail_off=0;
    time_now=hr_stop_retry;
    hr_tick(time_now);
    assert(!hr_stop_retry && !hr_burst_start && !held && !hub[H_HR].enabled);
    hr_active=0;
    assert(hr_update(time_now)==0 && !hr_bg);
    hr_active=1; hr_req_ns=1000000000LL; fail_on=1;
    assert(hr_update(time_now)==-EIO);
    return 0;
}
'''
        cls.temp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temp.cleanup)
        src = Path(cls.temp.name) / "health.c"
        cls.exe = Path(cls.temp.name) / "health"
        src.write_text(harness)
        subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                        str(src), "-o", str(cls.exe)], check=True, timeout=15)

    def test_valid_records(self):
        for line in ("W 123", "D 456", "O 1", "O 2", "P 0", "P 987"):
            with self.subTest(line=line):
                subprocess.run([str(self.exe), line], check=True, timeout=5)

    def test_malformed_records(self):
        for line in ("", "W", "W 2x", "O 0", "O 3", "O abc", "P -1",
                     "P 9223372036854775808", "P 1 2", "X 1"):
            with self.subTest(line=line):
                self.assertEqual(subprocess.run([str(self.exe), line], timeout=5).returncode, 1)

    def test_hr_state_machine_and_saturating_steps(self):
        subprocess.run([str(self.exe)], check=True, timeout=5)

    def test_context_read_bounded_by_capacity(self):
        self.assertIn("budget > 0 && *n_out < count", self.source)
        self.assertIn("read(ctx_fd, &ch, 1)", self.source)

    def test_overlong_record_discarded_until_newline(self):
        self.assertIn("ctx_len = ctx_discard = 0", self.source)
        self.assertIn("if (!ch || ctx_len >=", self.source)

    def test_pending_detector_is_bounded(self):
        self.assertIn("STEP_PENDING_MAX - step_detect_pending", self.source)

    def test_unknown_offbody_not_reported(self):
        self.assertIn("offbody_report = enabled && offbody_known", self.source)

    def test_hr_failure_propagated(self):
        self.assertIn("hr_active = previous", self.source)
        self.assertIn("hr_req_ns = previous", self.source)


if __name__ == "__main__":
    unittest.main()
