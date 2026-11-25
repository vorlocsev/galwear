#!/usr/bin/env python3
"""Compile the actual patched pcm_sync_ptr with a fake ioctl backend, not ALSA."""
import argparse
from pathlib import Path
import subprocess
import tempfile

HARNESS = r"""
#include <assert.h>
#include <errno.h>
#include <stddef.h>
#define PCM_MMAP 1
#define SNDRV_PCM_SYNC_PTR_HWSYNC 1
#define SNDRV_PCM_SYNC_PTR_APPL 2
#define SNDRV_PCM_SYNC_PTR_AVAIL_MIN 4
#define SNDRV_PCM_IOCTL_HWSYNC 100
#define SNDRV_PCM_IOCTL_SYNC_PTR 101
#define ioctl(...) (0)
struct fake_sync { int flags, appl, avail; };
struct fake_kernel { int appl, avail, fail; };
struct ops { int (*ioctl)(void *, int, struct fake_sync *); };
struct pcm { int fd, flags; struct fake_sync *sync_ptr; struct ops *ops; void *data; };
static int oops(struct pcm *pcm, int err, const char *msg) {
    (void)pcm; (void)err; (void)msg; return -1;
}
static int fake_ioctl(void *data, int request, struct fake_sync *sync) {
    struct fake_kernel *k = data;
    assert(request == SNDRV_PCM_IOCTL_SYNC_PTR);
    if (k->fail) { errno = EIO; return -1; }
    if (sync->flags & SNDRV_PCM_SYNC_PTR_APPL) sync->appl = k->appl;
    else k->appl = sync->appl;
    if (sync->flags & SNDRV_PCM_SYNC_PTR_AVAIL_MIN) sync->avail = k->avail;
    else k->avail = sync->avail;
    return 0;
}
"""
CASES = r"""
int main(void) {
    struct fake_kernel k = {640, 160, 0};
    struct fake_sync sync = {0, 0, 0};
    struct ops ops = {fake_ioctl};
    struct pcm pcm = {0, 0, &sync, &ops, &k};
    assert(pcm_sync_ptr(&pcm, 0) == 0);
    assert(k.appl == 640 && k.avail == 160);
    assert(sync.appl == 640 && sync.avail == 160);
    k.appl = 960;
    assert(pcm_sync_ptr(&pcm, SNDRV_PCM_SYNC_PTR_HWSYNC) == 0);
    assert(k.appl == 960 && sync.appl == 960);
    assert(sync.flags == 7);
    pcm.flags = PCM_MMAP;
    sync.appl = 1120;
    sync.avail = 80;
    assert(pcm_sync_ptr(&pcm, 0) == 0);
    assert(k.appl == 1120 && k.avail == 80 && sync.flags == 0);
    k.fail = 1;
    assert(pcm_sync_ptr(&pcm, 0) == -1);
    return 0;
}
"""


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--source", required=True, type=Path)
    args = p.parse_args()
    text = args.source.read_text()
    start = text.index("static int pcm_sync_ptr(struct pcm *pcm, int flags)")
    end = text.index("\nstatic int pcm_hw_mmap_status", start)
    function = text[start:end]
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        code = root / "sync_test.c"
        binary = root / "sync_test"
        code.write_text(HARNESS + "\n" + function + "\n" + CASES)
        subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                        str(code), "-o", str(binary)], check=True)
        subprocess.run([str(binary)], check=True, timeout=5)
    print("PASS: mocked PCM query preserves kernel pointers; mmap commit and ioctl errors preserved")


if __name__ == "__main__":
    main()
