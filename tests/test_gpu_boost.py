"""Host compile and fixture checks for bounded Mali/CPU input boost."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class GpuBoostTests(unittest.TestCase):
    def test_boost_source_compiles(self):
        subprocess.run(["cc", "-std=gnu11", "-Wall", "-Wextra", "-Werror",
                        "-fsyntax-only", str(ROOT / "src/tools/r800boost.c")],
                       check=True, timeout=15)

    def test_actual_gpu_readback_parser(self):
        source = (ROOT / "src/tools/r800boost.c").read_text()
        parser = source[source.index("static int gpu_requested("):source.index("static int restore_if_owned(")]
        harness = r'''
#include <assert.h>
#include <stdio.h>
#include <string.h>
''' + parser + r'''
int main(void) {
    assert(gpu_requested("-1")==0);
    assert(gpu_requested("667 / 667")==667);
    assert(gpu_requested("400 / 667")==667);
    assert(gpu_requested("400 / 0")==0);
    assert(gpu_requested("667")==-1);
    assert(gpu_requested("667 / 667 extra")==-1);
    assert(gpu_requested("-2 / 667")==-1);
    return 0;
}
'''
        with tempfile.TemporaryDirectory() as d:
            src, exe = Path(d)/"parser.c", Path(d)/"parser"
            src.write_text(harness)
            subprocess.run(["cc", "-Wall", "-Wextra", "-Werror", str(src),
                            "-o", str(exe)], check=True, timeout=15)
            subprocess.run([str(exe)], check=True, timeout=5)

    def test_cleanup_on_shutdown(self):
        s = (ROOT / "src/tools/r800boost.c").read_text()
        self.assertIn("sigaction(SIGTERM", s)
        self.assertIn("POLLERR | POLLHUP | POLLNVAL", s)
        self.assertIn("if (gpu_owned && restore_gpu())", s)
        self.assertIn("restore_if_owned(POLICY", s)

    def test_helper_preserves_existing_lock(self):
        s = (ROOT / "payload/android-helper.sh").read_text().split("# ---- GPU.",1)[1].split("# ---- after boot:",1)[0]
        self.assertIn('"667 / 667")', s)
        self.assertIn("existing lock ($state); leaving it alone", s)
        self.assertNotIn("grep -q 667", s)
        self.assertNotIn('> "$G/dvfs_max_lock"', s)

    def test_boost_does_not_write_thermal_or_max_controls(self):
        s = (ROOT / "src/tools/r800boost.c").read_text()
        self.assertNotIn('GPU "dvfs_max_lock"', s)
        self.assertNotIn('GPU "tmu"', s)
        self.assertIn("MAX_BOOST_MS 5000", s)
        self.assertIn("budget > 0", s)


if __name__ == "__main__":
    unittest.main()
