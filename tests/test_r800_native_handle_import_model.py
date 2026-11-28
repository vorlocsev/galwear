"""Host-only native_handle import ownership model; not a donor IMapper."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = r'''
#define _GNU_SOURCE
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <cutils/native_handle.h>

/* Test-only bounded clone. Caller owns the source; a successful import
 * owns independent CLOEXEC descriptors. No Android HAL is invoked. */
static int import_model(const native_handle_t *src, size_t bytes,
                        native_handle_t **out)
{
    if (!out || *out || !src || bytes < sizeof(*src) ||
        src->version != (int)sizeof(*src) ||
        src->numFds < 1 || src->numFds > 8 ||
        src->numInts < 0 || src->numInts > 128)
        return -EINVAL;
    size_t need = sizeof(*src) + sizeof(int) *
                  (size_t)(src->numFds + src->numInts);
    if (bytes != need) return -EINVAL;
    native_handle_t *copy = calloc(1, need);
    if (!copy) return -ENOMEM;
    copy->version = src->version;
    copy->numFds = src->numFds;
    copy->numInts = src->numInts;
    for (int i = 0; i < src->numFds; ++i) {
        int fd = fcntl(src->data[i], F_DUPFD_CLOEXEC, 0);
        if (fd < 0) {
            int error = errno;
            while (i > 0) close(copy->data[--i]);
            free(copy);
            return -error;
        }
        copy->data[i] = fd;
    }
    memcpy(copy->data + copy->numFds, src->data + src->numFds,
           sizeof(int) * (size_t)src->numInts);
    *out = copy;
    return 0;
}

static int free_model(native_handle_t **owned)
{
    if (!owned || !*owned) return -EINVAL;
    native_handle_t *h = *owned;
    *owned = NULL;
    int ret = 0;
    for (int i = 0; i < h->numFds; ++i)
        if (close(h->data[i]) && !ret) ret = -errno;
    free(h);
    return ret;
}

static int fd_count(void)
{
    DIR *dir = opendir("/proc/self/fd");
    assert(dir);
    int count = 0;
    struct dirent *e;
    while ((e = readdir(dir)))
        if (strcmp(e->d_name, ".") && strcmp(e->d_name, "..")) ++count;
    assert(!closedir(dir));
    return count;
}

int main(int argc, char **argv)
{
    assert(argc == 2);
    int baseline = fd_count(), p[2];
    assert(!pipe(p));
    const size_t bytes = sizeof(native_handle_t) + 6*sizeof(int);
    native_handle_t *raw = calloc(1, bytes), *owned = NULL;
    assert(raw);
    raw->version = sizeof(*raw);
    raw->numFds = 2;
    raw->numInts = 4;
    raw->data[0] = p[0]; raw->data[1] = p[1];
    raw->data[2] = 1; raw->data[3] = 360;
    raw->data[4] = 360; raw->data[5] = 368;
    if (!strcmp(argv[1], "copy")) {
        assert(!import_model(raw, bytes, &owned));
        assert(owned != raw && owned->data[0] != p[0] && owned->data[1] != p[1]);
        assert(owned->numFds == 2 && owned->numInts == 4);
        assert(!memcmp(owned->data+2, raw->data+2, 4*sizeof(int)));
        assert(fcntl(owned->data[0], F_GETFD) == FD_CLOEXEC);
        assert(fcntl(owned->data[1], F_GETFD) == FD_CLOEXEC);
        assert(fd_count() == baseline+4);
        assert(!free_model(&owned) && !owned);
        assert(fcntl(p[0], F_GETFD) >= 0 && fcntl(p[1], F_GETFD) >= 0);
    } else if (!strcmp(argv[1], "source_close")) {
        assert(!import_model(raw, bytes, &owned));
        assert(!close(p[0]) && !close(p[1]));
        p[0] = p[1] = -1;
        char ch = 0;
        assert(write(owned->data[1], "q", 1) == 1);
        assert(read(owned->data[0], &ch, 1) == 1 && ch == 'q');
        assert(!free_model(&owned));
    } else if (!strcmp(argv[1], "partial_failure")) {
        raw->data[1] = -1;
        assert(import_model(raw, bytes, &owned) == -EBADF && !owned);
        assert(fd_count() == baseline+2);
        assert(fcntl(p[0], F_GETFD) >= 0 && fcntl(p[1], F_GETFD) >= 0);
    } else if (!strcmp(argv[1], "malformed")) {
        assert(import_model(raw, sizeof(*raw)-1, &owned) == -EINVAL);
        assert(import_model(raw, bytes-1, &owned) == -EINVAL);
        assert(import_model(raw, bytes+1, &owned) == -EINVAL);
        raw->version = 0;
        assert(import_model(raw, bytes, &owned) == -EINVAL);
        raw->version = sizeof(*raw);
        raw->numFds = 9;
        assert(import_model(raw, bytes, &owned) == -EINVAL);
        raw->numFds = 2; raw->numInts = -1;
        assert(import_model(raw, bytes, &owned) == -EINVAL);
        raw->numInts = 129;
        assert(import_model(raw, bytes, &owned) == -EINVAL);
        assert(!owned && fd_count() == baseline+2);
    } else if (!strcmp(argv[1], "duplicate")) {
        assert(!import_model(raw, bytes, &owned));
        native_handle_t *saved = owned;
        assert(import_model(raw, bytes, &owned) == -EINVAL && owned == saved);
        assert(!free_model(&owned));
        assert(free_model(&owned) == -EINVAL);
    } else if (!strcmp(argv[1], "cycles")) {
        for (int i = 0; i < 100; ++i) {
            assert(!import_model(raw, bytes, &owned));
            assert(!free_model(&owned));
            assert(fd_count() == baseline+2);
        }
    } else abort();
    if (p[0] >= 0) assert(!close(p[0]));
    if (p[1] >= 0) assert(!close(p[1]));
    free(raw);
    assert(!owned && fd_count() == baseline);
    return 0;
}
'''


class NativeHandleImportModelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(temp.cleanup)
        root = Path(temp.name)
        source = root / "import.c"
        source.write_text(SOURCE)
        cls.binary = root / "import"
        subprocess.run(["cc", "-std=gnu11", "-Wall", "-Wextra", "-Werror",
                        "-I" + str(ROOT / "src/hal/include"), str(source),
                        "-o", str(cls.binary)], check=True, timeout=30)

    def run_case(self, case):
        subprocess.run([str(self.binary), case], check=True, timeout=10)

    def test_copy_metadata_and_independent_cloexec_fds(self):
        self.run_case("copy")

    def test_source_close_does_not_invalidate_import(self):
        self.run_case("source_close")

    def test_partial_dup_failure_rolls_back(self):
        self.run_case("partial_failure")

    def test_malformed_counts_and_truncated_payload(self):
        self.run_case("malformed")

    def test_duplicate_import_and_free_rejected(self):
        self.run_case("duplicate")

    def test_repeated_import_free_does_not_leak(self):
        self.run_case("cycles")


if __name__ == "__main__":
    unittest.main()
