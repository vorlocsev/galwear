"""Host fixtures for fixed-stride HWC layer validation; not donor ABI evidence."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class HwcAdapterAbiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = (ROOT / "src/hal/hwcomposer_r800.c").read_text()
        s = cls.source
        helper = s[s.index("#define R800_MAX_LAYERS"):s.index("\n/*", s.index("static int validate_displays("))]
        harness = r'''
#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#define HWC_FRAMEBUFFER_TARGET 3
typedef struct { int32_t compositionType; char padding[92]; } hwc_layer_1_t;
typedef struct { size_t numHwLayers; hwc_layer_1_t hwLayers[0]; } hwc_display_contents_1_t;
struct r800_hwc { size_t layer_stride; };
''' + helper + r'''
int main(int argc, char **argv) {
    assert(argc == 3);
    struct r800_hwc h = {.layer_stride=select_layer_stride(argv[1])};
    int mode = atoi(argv[2]);
    if (mode == 0) { assert(!h.layer_stride); return 0; }
    assert(h.layer_stride == (strcmp(argv[1],"96") ? 100 : 96));
    size_t count = mode == 4 ? 257 : 3;
    size_t allocated = mode == 4 ? 0 : count * h.layer_stride;
    hwc_display_contents_1_t *c = calloc(1, sizeof(*c)+allocated);
    assert(c);
    c->numHwLayers=count;
    if (mode != 4) {
        int target = HWC_FRAMEBUFFER_TARGET;
        if (mode != 2)
            memcpy((char *)c->hwLayers+2*h.layer_stride,&target,sizeof(target));
        if (mode == 3)
            memcpy((char *)c->hwLayers,&target,sizeof(target));
    }
    hwc_display_contents_1_t *list[1]={c};
    assert(validate_displays(&h,1,list)==(mode==1 ? 0 : -EINVAL));
    assert(validate_displays(&h,4,list)==-EINVAL);
    assert(validate_displays(&h,1,NULL)==-EINVAL);
    assert(validate_displays(&h,0,NULL)==0);
    free(c);
    return 0;
}
'''
        cls.tmp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.tmp.cleanup)
        src = Path(cls.tmp.name) / "adapter.c"
        cls.exe = Path(cls.tmp.name) / "adapter"
        src.write_text(harness)
        subprocess.run(["cc", "-std=gnu11", "-Wall", "-Wextra", "-Werror",
                        str(src), "-o", str(cls.exe)], check=True, timeout=15)

    def run_case(self, prop, mode):
        subprocess.run([str(self.exe), prop, str(mode)], check=True, timeout=5)

    def test_default_and_explicit_donor(self):
        for value in ("", "100"):
            self.run_case(value, 1)

    def test_aosp(self):
        self.run_case("96", 1)

    def test_invalid_property(self):
        for value in ("0", "auto", "100x", "120"):
            self.run_case(value, 0)

    def test_target_missing_or_duplicate(self):
        for value in ("96", "100"):
            for mode in (2, 3):
                self.run_case(value, mode)

    def test_oversized_list_rejected_without_read(self):
        self.run_case("100", 4)

    def test_no_alternate_stride_probe(self):
        self.assertNotIn("static size_t g_stride", self.source)
        self.assertNotIn("cand[2]", self.source)
        self.assertIn("h->layer_stride = stride;", self.source)

    def test_abi_offsets_checked(self):
        self.assertIn("offsetof(hwc_layer_1_t, acquireFenceFd) == 64", self.source)
        self.assertIn("offsetof(hwc_layer_1_t, releaseFenceFd) == 68", self.source)

    def test_overlay_index_validated(self):
        self.assertIn("h->ovl_idx[w] >= c->numHwLayers", self.source)


if __name__ == "__main__":
    unittest.main()
