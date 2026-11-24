"""Compile actual HFP start/stop functions against host-only PCM/mixer stubs."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src/hal/audio_r800.c"

STUB = r'''
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#define CARD 0
#define PCM_OUT 1
#define PCM_IN 2
#define PCM_FORMAT_S16_LE 0
#define LOGE(...) ((void)0)
#define LOGI(...) ((void)0)
struct pcm { int slot; };
struct pcm_config { unsigned channels, rate, format, period_size, period_count,
    start_threshold, stop_threshold; };
struct mix_setting { const char *name, *str; int val; };
struct stream { pthread_mutex_t lock; bool standby; };
struct r800_audio_device { bool hfp_active; int hfp_rate, hfp_volume;
    struct stream *out, *in; struct pcm *hfp_pcm[4]; };
static const struct mix_setting spk_off[] = {{"speaker",NULL,0}};
static const struct mix_setting mic_off[] = {{"mic",NULL,0}};
static int fail_slot, fail_mode, calls, live, stops, mixer_calls;
static int prop_int(const char *p,int d,int l,int h) { return d; }
static int apply_mixer(const struct mix_setting *s,size_t n) {
    mixer_calls++;
    return fail_mode == 4 && mixer_calls == 1 ? -EIO : 0;
}
static void do_standby(struct stream *s) { s->standby = true; }
static void in_do_standby(struct stream *s) { s->standby = true; }
static struct pcm *pcm_open(int card,int dev,unsigned flags,struct pcm_config *cfg) {
    int i = calls++;
    if (i == fail_slot && fail_mode == 1) return NULL;
    struct pcm *p = malloc(sizeof(*p)); assert(p); p->slot = i; live++; return p;
}
static int pcm_is_ready(struct pcm *p) { return !(p->slot == fail_slot && fail_mode == 2); }
static int pcm_prepare(struct pcm *p) { return 0; }
static int pcm_start(struct pcm *p) { return p->slot == fail_slot && fail_mode == 3 ? -EIO : 0; }
static int pcm_stop(struct pcm *p) { stops++; return 0; }
static void pcm_close(struct pcm *p) { assert(p && live > 0); live--; free(p); }
static const char *pcm_get_error(struct pcm *p) { return "fixture"; }
'''
MAIN = r'''
int main(int argc,char **argv) {
    assert(argc == 3);
    fail_slot = atoi(argv[1]); fail_mode = atoi(argv[2]);
    struct stream out = {.lock=PTHREAD_MUTEX_INITIALIZER}, in = {.lock=PTHREAD_MUTEX_INITIALIZER};
    struct r800_audio_device a = {.hfp_rate=8000,.hfp_volume=11,.out=&out,.in=&in};
    int rc = hfp_start(&a);
    assert(out.standby && in.standby);
    if (fail_mode) {
        assert(rc == -EIO && !a.hfp_active && live == 0);
        for(int i=0;i<4;i++) assert(!a.hfp_pcm[i]);
        assert(mixer_calls >= 2);
    } else {
        assert(rc == 0 && a.hfp_active && live == 4);
        assert(hfp_start(&a) == 0 && live == 4);
        hfp_stop(&a);
        assert(!a.hfp_active && live == 0 && stops == 4);
        hfp_stop(&a);
        assert(live == 0 && stops == 4);
    }
    assert(pthread_mutex_trylock(&out.lock) == 0);
    pthread_mutex_unlock(&out.lock);
    assert(pthread_mutex_trylock(&in.lock) == 0);
    pthread_mutex_unlock(&in.lock);
    return 0;
}
'''


class AudioRecoveryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = SOURCE.read_text()
        start = cls.source.index("#define MEDIA_DAC_GAIN")
        end = cls.source.index('/* value of "key="', start)
        cls.tmp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.tmp.cleanup)
        src = Path(cls.tmp.name) / "hfp.c"
        cls.exe = Path(cls.tmp.name) / "hfp"
        src.write_text(STUB + cls.source[start:end] + MAIN)
        subprocess.run(["cc", "-std=c11", "-pthread", "-Wall", "-Werror=implicit-function-declaration",
                        str(src), "-o", str(cls.exe)], check=True, timeout=15)

    def run_hfp(self, slot, mode):
        subprocess.run([str(self.exe), str(slot), str(mode)], check=True, timeout=5)

    def test_success_and_idempotent_stop(self):
        self.run_hfp(-1, 0)

    def test_each_open_failure_rolls_back(self):
        for slot in range(4):
            with self.subTest(slot=slot):
                self.run_hfp(slot, 1)

    def test_each_not_ready_rolls_back(self):
        for slot in range(4):
            with self.subTest(slot=slot):
                self.run_hfp(slot, 2)

    def test_each_start_failure_rolls_back(self):
        for slot in range(4):
            with self.subTest(slot=slot):
                self.run_hfp(slot, 3)

    def test_mixer_failure_rolls_back(self):
        self.run_hfp(-1, 4)

    def test_pcm_progress_guards_present(self):
        self.assertIn("count <= 0 || (size_t)count > n", self.source)
        self.assertIn("r <= 0 || (size_t)r > n", self.source)
        self.assertIn("out->written += done", self.source)

    def test_mic_and_hfp_flags_atomic(self):
        self.assertIn("_Atomic bool mic_mute;", self.source)
        self.assertIn("_Atomic bool hfp_active;", self.source)


if __name__ == "__main__":
    unittest.main()
