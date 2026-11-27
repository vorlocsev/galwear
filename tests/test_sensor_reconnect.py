"""Host fixture for actual SSP input recovery helpers; no real sysfs access."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class SensorReconnectTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = (ROOT / "src/hal/sensors_r800.c").read_text()
        s = cls.source
        actual = s[s.index("static void input_lost("):s.index("static int valid(")]
        harness = r'''
#include <assert.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#define INPUT_RETRY_NS 5000000000LL
#define LOGE(...) ((void)0)
enum { H_ACCEL=1,H_COUNT=3 };
struct hub_sensor {
    int fd,enabled,dropped;
    int v[6],ts[4];
    int64_t period_ns;
    const char *delay_node;
};
static struct hub_sensor hub[H_COUNT];
static int64_t input_retry_at;
static int input_restore_pending;
static int scan_count,mask_count,delay_count,closed,found,fail;
static int close(int fd) { assert(fd>=0); closed++; return 0; }
static int open_inputs(void) {
    scan_count++;
    if(found && hub[1].fd<0) {hub[1].fd=42;hub[1].dropped=1;return 1;}
    return 0;
}
static int write_sysfs(const char *node,long long ns) {
    assert(node && ns>0);
    delay_count++;
    return 0;
}
static int apply_enable_mask(void) {
    mask_count++;
    return fail ? -EIO : 0;
}
''' + actual + r'''
int main(void) {
    hub[1].fd=10;
    hub[1].enabled=1;
    hub[1].period_ns=20000000;
    hub[1].delay_node="accel_poll_delay";
    hub[1].v[0]=123; hub[1].ts[0]=456;
    hub[2].fd=11;
    assert(recover_inputs(100)==-1 && !scan_count && !mask_count);
    input_lost(&hub[1]);
    assert(closed==1 && hub[1].fd==-1 && hub[1].enabled);
    assert(!hub[1].v[0] && !hub[1].ts[0] && hub[1].dropped);
    assert(recover_inputs(100)==5000 && scan_count==1);
    assert(recover_inputs(1000000100LL)==4000 && scan_count==1);
    found=1; fail=1;
    assert(recover_inputs(5000000100LL)==5000 && scan_count==2);
    assert(hub[1].fd==42 && hub[1].enabled && input_restore_pending);
    assert(delay_count==1 && hub[1].dropped);
    fail=0;
    assert(recover_inputs(10000000100LL)==-1);
    assert(!input_restore_pending && delay_count==2 && scan_count==2);
    assert(mask_count==3);
    assert(recover_inputs(15000000100LL)==-1 && scan_count==2);
    return 0;
}
'''
        cls.tmp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.tmp.cleanup)
        src = Path(cls.tmp.name) / "reconnect.c"
        cls.exe = Path(cls.tmp.name) / "reconnect"
        src.write_text(harness)
        subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                        str(src), "-o", str(cls.exe)], check=True, timeout=15)

    def test_actual_reconnect_and_retry(self):
        subprocess.run([str(self.exe)], check=True, timeout=5)

    def test_missing_input_is_not_fatal_to_poll(self):
        self.assertIn("input_lost(&hub[idx[i]]);", self.source)
        self.assertIn("input_lost(s);", self.source)

    def test_restore_uses_existing_mask_merge(self):
        s = self.source.split("static int recover_inputs(", 1)[1].split("static int valid(", 1)[0]
        self.assertIn("r = apply_enable_mask();", s)
        self.assertNotIn('write_sysfs("enable"', s)

    def test_rescan_deadline_limits_poll_timeout(self):
        self.assertIn("tmo = recover_tmo;", self.source)

    def test_first_reconnected_frame_discarded(self):
        self.assertIn("hub[h].dropped = 1;", self.source)


if __name__ == "__main__":
    unittest.main()
