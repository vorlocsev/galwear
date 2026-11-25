"""Compile actual close functions with a host-only lifecycle harness."""
from pathlib import Path
import subprocess
import tempfile
import unittest

SOURCE = Path(__file__).resolve().parents[1] / "src/hal/audio_r800.c"
STUB = r"""
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
struct audio_hw_device { int dummy; };
typedef struct { int dummy; } hw_device_t;
struct audio_stream { int dummy; };
struct audio_stream_out { struct audio_stream common; };
struct audio_stream_in { struct audio_stream common; };
struct r800_stream_out { struct audio_stream_out stream; pthread_mutex_t lock; };
struct r800_stream_in { struct audio_stream_in stream; pthread_mutex_t lock; };
struct r800_audio_device { pthread_mutex_t lock, route_lock;
    struct r800_stream_out *out; struct r800_stream_in *in; };
static struct r800_audio_device *active;
static int out_closed, in_closed, hfp_stopped;
static void out_standby(struct audio_stream *s) {
    assert(s == &active->out->stream.common);
    assert(pthread_mutex_trylock(&active->lock) == EBUSY);
    out_closed++;
}
static void in_standby(struct audio_stream *s) {
    assert(s == &active->in->stream.common);
    assert(pthread_mutex_trylock(&active->lock) == EBUSY);
    in_closed++;
}
static void hfp_stop(struct r800_audio_device *a) {
    assert(a == active && !a->out && !a->in);
    assert(pthread_mutex_trylock(&a->lock) == EBUSY);
    hfp_stopped++;
}
"""
MAIN = r"""
int main(void) {
    struct r800_audio_device *a = calloc(1, sizeof(*a));
    assert(a);
    active = a;
    assert(!pthread_mutex_init(&a->lock, NULL));
    assert(!pthread_mutex_init(&a->route_lock, NULL));
    a->out = calloc(1, sizeof(*a->out));
    a->in = calloc(1, sizeof(*a->in));
    assert(a->out && a->in);
    assert(!pthread_mutex_init(&a->out->lock, NULL));
    assert(!pthread_mutex_init(&a->in->lock, NULL));
    hw_device_t *d = (hw_device_t *)a;
    struct audio_hw_device *dev = (struct audio_hw_device *)a;
    assert(adev_close(NULL) == -EINVAL);
    assert(adev_close(d) == -EBUSY);
    assert(!out_closed && !in_closed && !hfp_stopped);
    assert(!pthread_mutex_trylock(&a->lock));
    pthread_mutex_unlock(&a->lock);
    struct audio_stream_out foreign = {0};
    adev_close_output_stream(dev, &foreign);
    adev_close_output_stream(dev, NULL);
    assert(!out_closed && a->out);
    adev_close_output_stream(dev, &a->out->stream);
    assert(out_closed == 1 && !a->out);
    assert(adev_close(d) == -EBUSY);
    adev_close_input_stream(dev, &a->in->stream);
    assert(in_closed == 1 && !a->in);
    assert(!adev_close(d));
    assert(hfp_stopped == 1);
    return 0;
}
"""


class AudioLifecycleTests(unittest.TestCase):
    def test_device_close_rejects_live_streams(self):
        source = SOURCE.read_text()
        functions = []
        for marker in ("static void adev_close_output_stream(",
                       "static void adev_close_input_stream(",
                       "static int adev_close("):
            body = source[source.index(marker):]
            functions.append(body[:body.index("\n}\n") + 3])
        with tempfile.TemporaryDirectory() as tmp:
            c = Path(tmp) / "lifecycle.c"
            exe = Path(tmp) / "lifecycle"
            c.write_text(STUB + "\n".join(functions) + MAIN)
            subprocess.run(["cc", "-std=c11", "-pthread", "-Wall", "-Wextra",
                            "-Werror", str(c), "-o", str(exe)], check=True, timeout=15)
            subprocess.run([str(exe)], check=True, timeout=5)

    def test_stream_mutex_failure_never_publishes_handle(self):
        source = SOURCE.read_text()
        for stream, kind in (("out", "output"), ("in", "input")):
            body = source[source.index("static int adev_open_" + kind + "_stream("):]
            body = body[:body.index("\n}\n")]
            self.assertIn("*stream_" + stream + " = NULL;", body)
            init = body.index("rc = pthread_mutex_init(&" + stream + "->lock, NULL)")
            publish = body.index("adev->" + stream + " = " + stream + ";")
            self.assertLess(init, publish)
            self.assertIn("free(" + stream + ");", body[init:publish])
            self.assertIn("return -rc;", body[init:publish])


if __name__ == "__main__":
    unittest.main()
