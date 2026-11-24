"""Host fixture for actual HWC power-mode transition and retry helpers."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class HwcPowerTransitionsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = (ROOT / "src/hal/hwcomposer_r800.c").read_text()
        s = cls.source
        resume = s[s.index("static int doze_resume(struct r800_hwc *h)\n{"):s.index("static void doze_presented(struct r800_hwc *h)\n{")]
        power = s[s.index("static int r800_set_power_mode("):s.index("static int r800_get_active_config(")]
        harness = r'''
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <pthread.h>
#include <string.h>
#define HWC_POWER_MODE_OFF 0
#define HWC_POWER_MODE_DOZE 1
#define HWC_POWER_MODE_NORMAL 2
#define HWC_POWER_MODE_DOZE_SUSPEND 3
#define R800_DISP_PWR_DOZE 1
#define R800_DISP_PWR_DOZE_SUSPEND 3
#define R800_S3CFB_POWER_MODE 100
#define FBIOBLANK 101
#define FB_BLANK_UNBLANK 0
#define LOGE(...) ((void)0)
#define LOGI(...) ((void)0)
typedef struct {int unused;} hwc_composer_device_1_t;
struct r800_hwc {
    int power_mode,doze_susp,power_uncertain,blanked,fb_fd;
    int64_t last_present_ns,power_retry_ns;
    pthread_cond_t doze_cond;
    pthread_mutex_t doze_lock;
};
static int fail, calls;
static int64_t now=100;
static int64_t mono_ns(void){return now;}
static int ioctl(int fd,unsigned long cmd,...){
    (void)fd;(void)cmd;calls++;
    if(fail){errno=EIO;return -1;}return 0;
}
static int r800_blank(hwc_composer_device_1_t *dev,int disp,int blank){
    (void)disp;
    if(fail)return -EIO;
    ((struct r800_hwc*)dev)->blanked=blank;
    return 0;
}
''' + resume + power + r'''
int main(void){
    struct r800_hwc h={.power_mode=HWC_POWER_MODE_NORMAL,
        .doze_cond=PTHREAD_COND_INITIALIZER,.doze_lock=PTHREAD_MUTEX_INITIALIZER};
    hwc_composer_device_1_t *d=(void*)&h;
    fail=1;
    assert(r800_set_power_mode(d,0,HWC_POWER_MODE_DOZE)==-EIO);
    assert(h.power_mode==HWC_POWER_MODE_NORMAL && h.power_uncertain);
    assert(doze_resume(&h)==-EIO);
    fail=0;
    assert(r800_set_power_mode(d,0,HWC_POWER_MODE_DOZE)==0);
    assert(h.power_mode==HWC_POWER_MODE_DOZE && !h.power_uncertain);
    h.doze_susp=1;fail=1;
    assert(doze_resume(&h)==-EIO && h.doze_susp && h.power_uncertain);
    int old=calls;
    assert(doze_resume(&h)==-EAGAIN && calls==old);
    now+=1000000000LL;fail=0;
    assert(doze_resume(&h)==0 && !h.doze_susp && !h.power_uncertain);
    assert(r800_set_power_mode(d,0,HWC_POWER_MODE_DOZE_SUSPEND)==0);
    fail=1;
    assert(r800_set_power_mode(d,0,HWC_POWER_MODE_NORMAL)==-EIO);
    assert(h.power_mode==HWC_POWER_MODE_DOZE_SUSPEND && h.doze_susp);
    fail=0;
    assert(r800_set_power_mode(d,0,HWC_POWER_MODE_NORMAL)==0);
    assert(!h.doze_susp && !h.power_uncertain);
    assert(r800_set_power_mode(d,0,HWC_POWER_MODE_OFF)==0 && h.blanked);
    return 0;
}
'''
        cls.tmp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.tmp.cleanup)
        src = Path(cls.tmp.name) / "power.c"
        cls.exe = Path(cls.tmp.name) / "power"
        src.write_text(harness)
        subprocess.run(["cc", "-std=gnu11", "-pthread", "-Wall", "-Wextra", "-Werror",
                        str(src), "-o", str(cls.exe)], check=True, timeout=15)

    def test_actual_power_state_and_retry(self):
        subprocess.run([str(self.exe)], check=True, timeout=5)

    def test_submission_holds_doze_lock(self):
        s = self.source.split("static int r800_set(",1)[1].split("static int64_t mono_ns(",1)[0]
        self.assertLess(s.index("pthread_mutex_lock(&h->doze_lock)"),s.index("doze_resume(h)"))
        self.assertLess(s.index("doze_presented(h)"),s.rindex("pthread_mutex_unlock(&h->doze_lock)"))

    def test_failed_resume_drops_frame_and_consumes_acquire_fences(self):
        s = self.source.split("if (doze_resume(h)",1)[1].split("static int calls;",1)[0]
        self.assertIn("close(l->acquireFenceFd);",s)
        self.assertIn("c->retireFenceFd = -1;",s)
        self.assertNotIn("wc_present(",s)

    def test_failed_idle_suspend_requires_recovery(self):
        self.assertIn("h->power_uncertain = 1; /* next frame must explicitly resume */",self.source)

    def test_boot_wake_marker_after_success(self):
        s = self.source.split('if (woke[0]',1)[1]
        self.assertLess(s.index('LOGE("unblanked panel")'),s.index('__system_property_set("debug.r800.hwc_woke", "1")'))


if __name__ == "__main__":
    unittest.main()
