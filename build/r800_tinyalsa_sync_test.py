"""Exercise the patched production sync_ptr against a mock kernel."""
from pathlib import Path
import subprocess
import sys
import tempfile

source = (Path(sys.argv[1]) / "src/pcm.c").read_text()
start = source.index("static int pcm_sync_ptr(")
end = source.index("static int pcm_hw_mmap_status(", start)
code = r"""
#include <assert.h>
#include <errno.h>
#include <stddef.h>
#define PCM_MMAP 1
#define SNDRV_PCM_SYNC_PTR_HWSYNC 1
#define SNDRV_PCM_SYNC_PTR_APPL 2
#define SNDRV_PCM_SYNC_PTR_AVAIL_MIN 4
#define SNDRV_PCM_IOCTL_SYNC_PTR 100
#define SNDRV_PCM_IOCTL_HWSYNC 101
struct sync { int flags, appl, avail; };
struct ops { int (*ioctl)(void *, int, struct sync *); };
struct pcm { int flags, fd; void *data; struct ops *ops; struct sync *sync_ptr; };
static int kernel_appl = 80, kernel_avail = 32, fail;
static int mock(void *data, int cmd, struct sync *s) {
    (void)data;
    assert(cmd == SNDRV_PCM_IOCTL_SYNC_PTR);
    if (fail) { errno = EIO; return -1; }
    if (s->flags & SNDRV_PCM_SYNC_PTR_APPL) s->appl = kernel_appl;
    else kernel_appl = s->appl;
    if (s->flags & SNDRV_PCM_SYNC_PTR_AVAIL_MIN) s->avail = kernel_avail;
    else kernel_avail = s->avail;
    return 0;
}
static int ioctl(int fd, int cmd) { (void)fd; (void)cmd; return 0; }
static void oops(struct pcm *p, int err, const char *msg)
{ (void)p; (void)err; (void)msg; }
""" + source[start:end] + r"""
int main(void) {
    struct sync s = {0};
    struct ops o = {mock};
    struct pcm p = {.ops=&o, .sync_ptr=&s};
    assert(!pcm_sync_ptr(&p, 0));
    assert(kernel_appl == 80 && s.appl == 80 && kernel_avail == 32);
    kernel_appl += 48;
    assert(!pcm_sync_ptr(&p, SNDRV_PCM_SYNC_PTR_HWSYNC));
    assert(kernel_appl == 128 && s.appl == 128 && s.flags == 7);
    p.flags = PCM_MMAP;
    s.appl = 160;
    assert(!pcm_sync_ptr(&p, 0));
    assert(kernel_appl == 160 && s.flags == 0);
    fail = 1;
    assert(pcm_sync_ptr(&p, 0) == -1);
    return 0;
}
"""
with tempfile.TemporaryDirectory() as tmp:
    c = Path(tmp) / "sync.c"
    exe = Path(tmp) / "sync"
    c.write_text(code)
    subprocess.run(["cc", "-std=c99", "-Wall", "-Wextra", "-Werror",
                    str(c), "-o", str(exe)], check=True, timeout=15)
    subprocess.run([str(exe)], check=True, timeout=5)
print("tinyalsa sync_ptr mock: PASS (non-mmap readback, mmap commit, error)")
