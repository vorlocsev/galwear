"""Host tests of the actual callback-copy helper and reader shutdown ordering."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class GnssLifecycleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = (ROOT / "src/hal/gps_r800.c").read_text()
        s = cls.source
        types = s[s.index("typedef int64_t GpsUtcTime;"):s.index("/* hardware/gps.h GnssSvStatus")]
        helper = s[s.index("static int copy_callbacks("):s.index("/* call with lock held */")]
        harness = r'''
#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <pthread.h>
#include <string.h>
''' + types + helper + r'''
static void system_info(const void *p) { (void)p; }
static void gnss_sv(void *p) { (void)p; }
int main(void) {
    GpsCallbacks src = {0}, dest;
    src.set_system_info_cb = system_info;
    src.gnss_sv_status_cb = gnss_sv;
    assert(copy_callbacks(&dest, NULL) == -EINVAL);
    src.size = offsetof(GpsCallbacks, set_system_info_cb) - 1;
    assert(copy_callbacks(&dest, &src) == -EINVAL);
    src.size++;
    assert(copy_callbacks(&dest, &src) == 0);
    assert(!dest.set_system_info_cb && !dest.gnss_sv_status_cb);
    src.size = offsetof(GpsCallbacks, gnss_sv_status_cb);
    assert(copy_callbacks(&dest, &src) == 0);
    assert(dest.set_system_info_cb == system_info && !dest.gnss_sv_status_cb);
    src.size = sizeof(src) - 1;
    assert(copy_callbacks(&dest, &src) == 0 && !dest.gnss_sv_status_cb);
    src.size = sizeof(src);
    assert(copy_callbacks(&dest, &src) == 0);
    assert(dest.gnss_sv_status_cb == gnss_sv);
    memset(&src, 0, sizeof(src));
    assert(dest.gnss_sv_status_cb == gnss_sv && dest.size == sizeof(dest));
    return 0;
}
'''
        cls.tmp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.tmp.cleanup)
        src = Path(cls.tmp.name) / "callbacks.c"
        cls.exe = Path(cls.tmp.name) / "callbacks"
        src.write_text(harness)
        subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                        str(src), "-o", str(cls.exe)], check=True, timeout=15)

    def test_actual_callback_copy(self):
        subprocess.run([str(self.exe)], check=True, timeout=5)

    def test_reader_stops_before_callback_storage_is_cleared(self):
        s = self.source.split("static int shutdown_reader(", 1)[1].split("static void gps_cleanup(", 1)[0]
        self.assertLess(s.index("atomic_store(&running, 0)"), s.index("pthread_join(tid, NULL)"))
        self.assertLess(s.index("pthread_join(tid, NULL)"), s.index("memset(&callbacks_owned"))
        self.assertIn("pthread_equal(pthread_self(), tid)", s)
        self.assertIn("shutdown(sock, SHUT_RDWR)", s)

    def test_thread_create_failure_checked(self):
        s = self.source.split("static int gps_init(", 1)[1].split("static int gps_start(", 1)[0]
        self.assertIn("r = pthread_create(&reader_thread, NULL, reader, NULL);", s)
        self.assertLess(s.index("return -r;"), s.index("reader_created = 1;"))

    def test_connect_is_nonblocking_and_not_published_after_stop(self):
        self.assertIn("SOCK_CLOEXEC | SOCK_NONBLOCK", self.source)
        self.assertIn("if (!atomic_load(&running)) {\n\t\t\t\tclose(fd);", self.source)

    def test_close_requires_join(self):
        s = self.source.split("static int dev_close(", 1)[1].split("static int dev_open(", 1)[0]
        self.assertLess(s.index("shutdown_reader()"), s.index("free(d)"))
        self.assertIn("if (r)\n\t\treturn r;", s)


if __name__ == "__main__":
    unittest.main()
