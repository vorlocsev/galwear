"""Exercise actual media start functions against deterministic PCM/mixer stubs."""
from pathlib import Path
import subprocess
import tempfile
import unittest

SOURCE = Path(__file__).resolve().parents[1] / "src/hal/audio_r800.c"
STUB = r"""
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#define LOGE(...) ((void)0)
#define LOGW(...) ((void)0)
#define LOGI(...) ((void)0)
#define CARD 0
#define SPK_DEVICE 0
#define MIC_DEVICE 9
#define OUT_CHANNELS 2
#define IN_HW_CHANNELS 2
#define OUT_RATE 48000
#define IN_RATE 48000
#define OUT_PERIOD 960
#define IN_PERIOD 960
#define OUT_PERIODS 4
#define IN_PERIODS 8
#define PCM_OUT 1
#define PCM_IN 2
#define PCM_MONOTONIC 4
#define PCM_FORMAT_S16_LE 0
#define RETRY_NS 1000000000LL
#define DEFAULT_ADC_GAIN 234
#define DEFAULT_DMIC_VOL 3
struct pcm { int dummy; };
struct pcm_config { int channels, rate, format, period_size, period_count,
                        start_threshold, stop_threshold; };
struct mix_setting { const char *name, *str; int val; };
static const struct mix_setting spk_on[] = {{"spk on",0,1}};
static const struct mix_setting spk_off[] = {{"spk off",0,0}};
static const struct mix_setting mic_on[] = {{"mic on",0,1}};
static const struct mix_setting mic_off[] = {{"mic off",0,0}};
struct adev { bool hfp_active, mic_mute; };
struct r800_stream_out { struct adev *adev; struct pcm *pcm; bool standby; int64_t next_open_ns; };
struct r800_stream_in { struct adev *adev; struct pcm *pcm; bool standby;
    int64_t next_open_ns; unsigned channels; uint64_t start_frames, frames_read; int peak; };
static int64_t clock_ns = 100;
static int fail_route, fail_open, fail_ready, calls, opens, closes, rollback;
static int64_t now_ns(void) { return clock_ns; }
static int prop_int(const char *name,int def,int lo,int hi)
{ (void)name; (void)lo; (void)hi; return def; }
static int apply_mixer(const struct mix_setting *s,size_t n) {
    (void)n;
    clock_ns += 10;
    if (s == mic_off || s == spk_off) { rollback++; return 0; }
    calls++;
    return calls == fail_route ? -EIO : 0;
}
static struct pcm *pcm_open(int c,int d,int flags,struct pcm_config *cfg) {
    (void)c; (void)d; (void)flags; (void)cfg;
    opens++;
    clock_ns += 20;
    return fail_open ? NULL : calloc(1,sizeof(struct pcm));
}
static int pcm_is_ready(struct pcm *p) { assert(p); return !fail_ready; }
static void pcm_close(struct pcm *p) { assert(p); closes++; free(p); }
static const char *pcm_get_error(struct pcm *p) { (void)p; return "fixture"; }
"""
MAIN = r"""
int main(int argc,char **argv) {
    assert(argc == 3);
    int input = atoi(argv[1]), mode = atoi(argv[2]);
    struct adev a = {0};
    struct r800_stream_out o = {.adev=&a,.standby=true};
    struct r800_stream_in i = {.adev=&a,.standby=true,.channels=1};
    fail_route = mode <= 2 ? mode : 0;
    fail_open = mode == 3; fail_ready = mode == 4;
    int rc = input ? start_input(&i) : start_output(&o);
    assert(rc == -EIO);
    assert(input ? i.standby && !i.pcm : o.standby && !o.pcm);
    int64_t deadline = input ? i.next_open_ns : o.next_open_ns;
    assert(deadline == clock_ns + RETRY_NS && rollback == 1);
    assert(opens == (mode >= 3));
    assert(closes == (mode == 4));
    int old_calls = calls;
    assert((input ? start_input(&i) : start_output(&o)) == -EAGAIN);
    assert(calls == old_calls);
    clock_ns = deadline;
    fail_route = fail_open = fail_ready = 0;
    a.hfp_active = true;
    assert((input ? start_input(&i) : start_output(&o)) == -EBUSY);
    assert(calls == old_calls);
    a.hfp_active = false;
    assert((input ? start_input(&i) : start_output(&o)) == 0);
    assert(input ? !i.standby && !i.next_open_ns : !o.standby && !o.next_open_ns);
    pcm_close(input ? i.pcm : o.pcm);
    return 0;
}
"""


class MediaRecoveryTests(unittest.TestCase):
    def test_actual_start_functions_retry_and_rollback(self):
        source = SOURCE.read_text()
        out = source[source.index("static int start_output("):
                     source.index("static ssize_t out_write(")]
        inp = source[source.index("static int start_input("):
                     source.index("static ssize_t in_read(")]
        with tempfile.TemporaryDirectory() as tmp:
            c = Path(tmp) / "media.c"
            exe = Path(tmp) / "media"
            c.write_text(STUB + out + inp + MAIN)
            subprocess.run(["cc", "-std=c11", "-Wall", "-Werror=implicit-function-declaration",
                            str(c), "-o", str(exe)], check=True, timeout=15)
            for input_stream in (0, 1):
                for mode in (1, 2, 3, 4):
                    if not input_stream and mode == 2:
                        continue
                    with self.subTest(input_stream=input_stream, mode=mode):
                        subprocess.run([str(exe), str(input_stream), str(mode)],
                                       check=True, timeout=5)

    def test_io_failure_uses_retry_deadline(self):
        source = SOURCE.read_text()
        self.assertIn("do_standby(out);\n            out->next_open_ns = now_ns() + RETRY_NS;", source)
        self.assertIn("in_do_standby(in);\n            in->next_open_ns = now_ns() + RETRY_NS;", source)


if __name__ == "__main__":
    unittest.main()
