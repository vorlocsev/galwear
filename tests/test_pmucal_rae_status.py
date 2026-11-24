"""Host C test for the exact added RAE status function, using fake MMIO."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

PATCH = Path(__file__).resolve().parents[1] / "src/kernel/r800-wearos.patch"
PREFIX = r"""
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <errno.h>
#include <string.h>
typedef uint32_t u32;
#define SZ_64K 65536U
#define PMUCAL_READ 0
struct pmucal_seq {
    u32 access_type, mask, offset, value;
    unsigned long base_pa;
    unsigned char *base_va;
};
static unsigned reads;
static u32 __raw_readl(const void *p) {
    u32 v;
    ++reads;
    memcpy(&v, p, sizeof(v));
    return v;
}
"""
SUFFIX = r"""
int main(void) {
    unsigned char mmio[SZ_64K] = {0};
    struct pmucal_seq seq[2] = {
        {PMUCAL_READ, 15, 4, 15, 1, mmio},
        {PMUCAL_READ, 15, 8, 15, 1, mmio}
    };
    u32 v = 15;
    assert(pmucal_rae_read_status(NULL, 1) == -EINVAL);
    assert(pmucal_rae_read_status(seq, 0) == -EINVAL);
    assert(reads == 0);
    assert(pmucal_rae_read_status(seq, 2) == 0);
    assert(seq[0].value == 15 && seq[1].value == 15);
    memcpy(mmio + 4, &v, 4);
    memcpy(mmio + 8, &v, 4);
    assert(pmucal_rae_read_status(seq, 2) == 1);
    reads = 0;
    seq[1].access_type = 2;
    assert(pmucal_rae_read_status(seq, 2) == -EINVAL && reads == 0);
    seq[1].access_type = PMUCAL_READ;
    seq[1].base_va = NULL;
    assert(pmucal_rae_read_status(seq, 2) == -ENXIO && reads == 0);
    seq[1].base_va = mmio;
    seq[1].base_pa = 0;
    assert(pmucal_rae_read_status(seq, 2) == -ENXIO && reads == 0);
    seq[1].base_pa = 1;
    seq[1].offset = 3;
    assert(pmucal_rae_read_status(seq, 2) == -EINVAL && reads == 0);
    seq[1].offset = SZ_64K;
    assert(pmucal_rae_read_status(seq, 2) == -EINVAL && reads == 0);
    seq[1].offset = SZ_64K - 4;
    memcpy(mmio + seq[1].offset, &v, 4);
    assert(pmucal_rae_read_status(seq, 2) == 1 && reads == 2);
    reads = 0;
    seq[1].mask = 0;
    assert(pmucal_rae_read_status(seq, 2) == -EINVAL && reads == 0);
    return 0;
}
"""


class RaeStatusHostTests(unittest.TestCase):
    def test_exact_function_with_fake_mmio(self):
        compiler = shutil.which("cc")
        self.assertIsNotNone(compiler, "host C compiler required")
        patch = PATCH.read_text(encoding="utf-8")
        file = "drivers/soc/samsung/cal-if/pmucal_rae.c"
        diff = patch.split(f"diff --git a/{file} b/{file}\n", 1)[1].split("\ndiff --git ", 1)[0]
        added = "\n".join(x[1:] for x in diff.splitlines()
                          if x.startswith("+") and not x.startswith("+++"))
        start = added.index("int pmucal_rae_read_status(")
        end = added.index("\n}", start) + 2
        function = added[start:end]
        with tempfile.TemporaryDirectory() as directory:
            src = Path(directory) / "test.c"
            exe = Path(directory) / "test"
            src.write_text(PREFIX + function + SUFFIX, encoding="utf-8")
            subprocess.run([compiler, "-std=gnu99", "-Wall", "-Wextra", "-Werror",
                            str(src), "-o", str(exe)], check=True, capture_output=True)
            subprocess.run([str(exe)], check=True, capture_output=True)


if __name__ == "__main__":
    unittest.main()
