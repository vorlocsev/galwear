"""Host tests for actual HWC geometry and padded plane validation."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class HwcBufferValidationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = (ROOT / "src/hal/hwcomposer_r800.c").read_text()
        s = cls.source
        actual = s[s.index("static int plane_bytes("):s.index("static int checked_buffer(")]
        harness = r'''
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stddef.h>
#include <limits.h>
#define HAL_PIXEL_FORMAT_RGBA_8888 1
#define HAL_PIXEL_FORMAT_RGBX_8888 2
#define HAL_PIXEL_FORMAT_BGRA_8888 5
typedef struct {int version,numFds,numInts,data[32];} native_handle_t;
typedef const native_handle_t *buffer_handle_t;
static int handle_ok(buffer_handle_t h) {return h && h->numFds==1 && h->numInts>=0 && h->numInts<=31;}
''' + actual + r'''
int main(void) {
    uint64_t need=0;
    assert(plane_bytes(360,360,384,&need)==0 && need==552960);
    assert(plane_bytes(360,360,359,&need)==-EINVAL);
    assert(plane_bytes(360,360,489,&need)==-EINVAL);
    assert(plane_bytes(INT_MAX,1,INT_MAX,&need)==-EINVAL);
    assert(check_plane_size(552960,552959,1)==-ENOSPC);
    assert(check_plane_size(552960,552960,0)==0);
    assert(check_plane_size(552960,0,0)==-ENODATA);
    assert(check_plane_size(552960,-1,1)==0);
    native_handle_t h={.numFds=1,.numInts=4,.data={7,1,360,360,384}};
    int stride=0,fmt=0;
    assert(handle_geom(&h,360,360,&stride,&fmt)==0 && stride==384 && fmt==1);
    h.data[1]=99;
    assert(handle_geom(&h,360,360,&stride,&fmt)==-EINVAL);
    h.data[1]=1;h.numInts=8;
    h.data[5]=5;h.data[6]=360;h.data[7]=360;h.data[8]=384;
    assert(handle_geom(&h,360,360,&stride,&fmt)==-EINVAL);
    assert(handle_geom(NULL,360,360,&stride,&fmt)==-EINVAL);
    return 0;
}
'''
        cls.tmp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.tmp.cleanup)
        src = Path(cls.tmp.name) / "geometry.c"
        cls.exe = Path(cls.tmp.name) / "geometry"
        src.write_text(harness)
        subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                        str(src), "-o", str(cls.exe)], check=True, timeout=15)

    def test_actual_geometry_and_size_helpers(self):
        subprocess.run([str(self.exe)], check=True, timeout=5)

    def test_all_render_paths_validate_buffers(self):
        for start, end in (("static int fb_present(", "static int wc_present("),
                           ("static int wc_present(", "/*\n * Layer stride"),
                           ("static int ovl_layer(", "static int ovl_present(")):
            s = self.source.split(start, 1)[1].split(end, 1)[0]
            self.assertIn("checked_buffer(h,", s)

    def test_unknown_size_is_explicit_opt_in(self):
        self.assertIn('h->allow_unknown_size = !strcmp(v, "1");', self.source)
        self.assertIn("return check_plane_size(need, have, h->allow_unknown_size);", self.source)

    def test_handle_full_span_probed(self):
        self.assertIn("return mapped_span(p, size);", self.source)

    def test_overlay_checks_crop_before_conversion(self):
        s = self.source.split("static int ovl_layer(",1)[1].split("static int ovl_present(",1)[0]
        self.assertIn("isfinite(l->sourceCropf.right)", s)
        self.assertNotIn("(int)l->sourceCropf", s)

    def test_no_guess_stride_fallback(self):
        self.assertNotIn("static int handle_stride(", self.source)
        self.assertIn("if (found++)", self.source)


if __name__ == "__main__":
    unittest.main()
