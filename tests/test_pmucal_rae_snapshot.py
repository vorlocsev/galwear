"""Host regression for exact PMUCAL save/restore functions with fake registers."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

PATCH = Path(__file__).resolve().parents[1] / "src/kernel/r800-wearos.patch"
PREFIX = r"""
#include <assert.h>
#include <stdbool.h>
#include <errno.h>
enum { PMUCAL_COND_SAVE_RESTORE, PMUCAL_SAVE_RESTORE, PMUCAL_READ,
       PMUCAL_COND_READ, PMUCAL_CHECK_SKIP, PMUCAL_COND_CHECK_SKIP,
       PMUCAL_WAIT, PMUCAL_WRITE };
struct pmucal_seq {
    unsigned access_type, value, reg;
    bool need_restore, need_skip, cond, match;
    int wait_result;
    unsigned writes, reads;
};
static bool pmucal_rae_check_condition(struct pmucal_seq *s) { return s->cond; }
static bool pmucal_rae_check_value(struct pmucal_seq *s) { return s->match; }
static void pmucal_rae_read(struct pmucal_seq *s) { s->value = s->reg; s->reads++; }
static void pmucal_rae_write(struct pmucal_seq *s) { s->reg = s->value; s->writes++; }
static int pmucal_rae_wait(struct pmucal_seq *s) { return s->wait_result; }
"""
SUFFIX = r"""
int main(void) {
    struct pmucal_seq s[3] = {
        {.access_type=PMUCAL_COND_SAVE_RESTORE, .reg=7, .cond=true},
        {.access_type=PMUCAL_SAVE_RESTORE, .reg=8},
        {.access_type=PMUCAL_SAVE_RESTORE, .reg=9}
    };
    pmucal_rae_save_seq(s, 3);
    s[0].cond=false; s[0].reg=17; s[0].need_skip=true;
    pmucal_rae_save_seq(s, 3);
    assert(!s[0].need_restore && !s[0].need_skip && s[0].reads==1);
    s[0].cond=true; s[1].reg=18;
    assert(pmucal_rae_restore_seq(s, 3)==0);
    assert(s[0].reg==17 && s[0].writes==0 && s[1].reg==8);
    assert(pmucal_rae_restore_seq(s, 3)==0 && s[1].writes==1);

    s[0].access_type=PMUCAL_CHECK_SKIP; s[0].match=true;
    pmucal_rae_save_seq(s, 3);
    assert(pmucal_rae_restore_seq(s, 3)==0);
    assert(s[1].writes==1 && !s[1].need_restore && !s[1].need_skip);
    s[0].match=false;
    assert(pmucal_rae_restore_seq(s, 3)==0 && s[1].writes==1);
    pmucal_rae_save_seq(s, 3);
    assert(pmucal_rae_restore_seq(s, 3)==0 && s[1].writes==2);

    s[0].access_type=PMUCAL_COND_CHECK_SKIP; s[0].cond=false;
    pmucal_rae_save_seq(s, 3);
    assert(pmucal_rae_restore_seq(s, 3)==0 && s[1].writes==2);
    s[0].access_type=PMUCAL_WAIT; s[0].wait_result=-ETIMEDOUT;
    pmucal_rae_save_seq(s, 3);
    assert(pmucal_rae_restore_seq(s, 3)==-ETIMEDOUT);
    assert(!s[1].need_restore && !s[2].need_restore);
    s[0].wait_result=0;
    assert(pmucal_rae_restore_seq(s, 3)==0 && s[1].writes==2);
    pmucal_rae_save_seq(s, 3);
    assert(pmucal_rae_restore_seq(s, 3)==0 && s[1].writes==3);

    s[0].access_type=PMUCAL_COND_SAVE_RESTORE; s[0].cond=true;
    pmucal_rae_save_seq(s, 3);
    s[0].cond=false;
    assert(pmucal_rae_restore_seq(s, 3)==0 && !s[0].need_restore);
    s[0].cond=true;
    assert(pmucal_rae_restore_seq(s, 3)==0 && s[0].writes==0);
    return 0;
}
"""


class RaeSnapshotTests(unittest.TestCase):
    def test_exact_functions(self):
        cc = shutil.which("cc")
        self.assertIsNotNone(cc, "host C compiler required")
        patch = PATCH.read_text(encoding="utf-8")
        name = "drivers/soc/samsung/cal-if/pmucal_rae.c"
        diff = patch.split(f"diff --git a/{name} b/{name}\n", 1)[1].split("\ndiff --git ", 1)[0]
        code = "\n".join(x[1:] for x in diff.splitlines()
                         if x.startswith((" ", "+")) and not x.startswith("+++"))
        start = code.index("void pmucal_rae_save_seq(")
        end = code.index("\n}", code.index("int pmucal_rae_restore_seq(")) + 2
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "test.c"
            exe = Path(directory) / "test"
            source.write_text(PREFIX + code[start:end] + SUFFIX, encoding="utf-8")
            subprocess.run([cc, "-std=gnu99", "-Wall", "-Wextra", "-Werror",
                            str(source), "-o", str(exe)], check=True, capture_output=True)
            subprocess.run([str(exe)], check=True, capture_output=True)


if __name__ == "__main__":
    unittest.main()
