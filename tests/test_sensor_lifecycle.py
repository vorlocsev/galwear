"""Host pthread/pipe fixture for actual Sensors HAL close and poll ownership."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class SensorLifecycleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = (ROOT / "src/hal/sensors_r800.c").read_text()
        s = cls.source
        state = s[s.index("static pthread_mutex_t lock"):s.index("/* pending flush-complete")]
        wake = s[s.index("static void wake_poll("):s.index("static int64_t now_ns(void);")]
        actual = s[s.index("static int dev_poll("):s.index("static int open_sensors(")]
        harness = r'''
#include <assert.h>
#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
typedef struct hw_device_t { int unused; } hw_device_t;
struct sensors_poll_device_t { int unused; };
typedef struct { int unused; } sensors_poll_device_1_t;
typedef int sensors_event_t;
enum { H_ACCEL=1, H_HR=2, H_COUNT=3, N_HANDLES=4 };
struct {int enabled,fd,dropped; int64_t period_ns; int v[6],ts[4];} hub[H_COUNT];
static int hr_active,hr_bg,hr_bursts,hr_skipped;
static int64_t hr_req_ns,hr_burst_start,hr_stop_retry,hr_next;
static int ctx_fd=-1,ctx_wfd=-1,ctx_len,ctx_discard,offbody_known,offbody_report,step_detect_pending;
static float offbody_state;
static int ctx_enabled[N_HANDLES],step_report[N_HANDLES],flush_pending[N_HANDLES];
static int fail_disable, unlocked;
static void hr_wakelock(int on) {assert(!on);unlocked++;}
static int apply_enable_mask(void) {
    for(int i=H_ACCEL;i<H_COUNT;i++) assert(!hub[i].enabled);
    return fail_disable ? -EIO : 0;
}
''' + state + wake + r'''
static int poll_events(sensors_event_t *data,int count) {
    (void)data;(void)count;
    struct pollfd p={.fd=wake_pipe[0],.events=POLLIN};
    assert(poll(&p,1,3000)==1);
    pthread_mutex_lock(&lock);
    assert(closing);
    pthread_mutex_unlock(&lock);
    return -ENODEV;
}
''' + actual + r'''
static void *worker(void *arg) {
    int event;
    assert(dev_poll(arg,&event,1)==-ENODEV);
    return NULL;
}
int main(void) {
    active_device=calloc(1,sizeof(*active_device));
    assert(active_device);
    hw_device_t *device=(hw_device_t *)active_device;
    assert(pipe(wake_pipe)==0);
    for(int i=H_ACCEL;i<H_COUNT;i++){hub[i].fd=-1;hub[i].enabled=1;}
    hr_burst_start=1;
    pthread_t t;
    assert(!pthread_create(&t,NULL,worker,device));
    for(;;) {
        pthread_mutex_lock(&lock);
        int ready=polling;
        pthread_mutex_unlock(&lock);
        if(ready) break;
        sched_yield();
    }
    int event;
    assert(dev_poll((void *)device,&event,1)==-EBUSY);
    fail_disable=1;
    assert(dev_close(device)==-EIO);
    assert(!pthread_join(t,NULL));
    assert(active_device==(void *)device && !closing && wake_pipe[0]>=0);
    assert(hub[H_ACCEL].enabled==1 && unlocked==0);
    fail_disable=0;
    assert(dev_close(device)==0);
    assert(!active_device && wake_pipe[0]==-1 && wake_pipe[1]==-1);
    assert(!hub[H_ACCEL].enabled && unlocked==1 && !hr_burst_start);
    return 0;
}
'''
        cls.tmp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.tmp.cleanup)
        src = Path(cls.tmp.name) / "lifecycle.c"
        cls.exe = Path(cls.tmp.name) / "lifecycle"
        src.write_text(harness)
        subprocess.run(["cc", "-std=gnu11", "-pthread", "-Wall", "-Wextra", "-Werror",
                        str(src), "-o", str(cls.exe)], check=True, timeout=15)

    def test_close_wakes_poll_and_can_retry_failed_disable(self):
        subprocess.run([str(self.exe)], check=True, timeout=5)

    def test_close_waits_before_fd_release(self):
        s = self.source.split("static int dev_close(",1)[1].split("static int open_sensors(",1)[0]
        self.assertLess(s.index("pthread_cond_wait"),s.index("close_fd(&hub[h].fd)"))
        self.assertLess(s.index("apply_enable_mask()"),s.index("hr_wakelock(0)"))

    def test_poll_has_bounded_input_budget(self):
        self.assertIn("int budget = 256;",self.source)
        self.assertIn("budget-- > 0",self.source)

    def test_single_device_and_poll(self):
        self.assertIn("if (active_device || closing)",self.source)
        self.assertIn("if (!device_ready(dev) || polling)",self.source)

    def test_close_preserves_step_total_but_resets_pending(self):
        s = self.source.split("static int dev_close(",1)[1].split("static int open_sensors(",1)[0]
        self.assertIn("step_detect_pending = 0;",s)
        self.assertNotIn("step_total =",s)


if __name__ == "__main__":
    unittest.main()
