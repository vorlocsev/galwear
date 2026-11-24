"""Execute the patched PMUCAL snapshot helper against a synthetic register array."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class PmucalSnapshotTests(unittest.TestCase):
    def test_new_snapshot_discards_stale_restore_flags(self):
        patch = (ROOT / "src/kernel/r800-wearos.patch").read_text()
        section = patch.split("diff --git a/drivers/soc/samsung/cal-if/pmucal_rae.c ", 1)[1].split("diff --git ", 1)[0]
        body = "\n".join(line[1:] for line in section.splitlines()
                         if line.startswith((" ", "+")) and not line.startswith("+++"))
        harness = r'''
#include <assert.h>
#include <stdbool.h>
enum {
    PMUCAL_COND_SAVE_RESTORE, PMUCAL_SAVE_RESTORE,
    PMUCAL_READ, PMUCAL_COND_READ, PMUCAL_CHECK_SKIP,
    PMUCAL_COND_CHECK_SKIP, PMUCAL_WAIT
};
struct pmucal_seq {
    int access_type, value, reg, condition;
    bool need_restore, need_skip;
};
static int reads;
static bool pmucal_rae_check_condition(struct pmucal_seq *s) {
    return s->condition;
}
static void pmucal_rae_read(struct pmucal_seq *s) {
    s->value = s->reg;
    reads++;
}
''' + body + r'''
int main(void) {
    struct pmucal_seq seq[] = {
        {PMUCAL_COND_SAVE_RESTORE,0,10,1,true,true},
        {PMUCAL_SAVE_RESTORE,0,20,0,true,true},
        {PMUCAL_READ,0,30,0,true,true},
        {PMUCAL_COND_READ,0,40,0,true,true},
        {PMUCAL_WAIT,0,0,0,true,true}
    };
    pmucal_rae_save_seq(seq,5);
    assert(reads==3 && seq[0].need_restore && seq[1].need_restore);
    for(int i=0;i<5;i++) assert(!seq[i].need_skip);
    for(int i=2;i<5;i++) assert(!seq[i].need_restore);
    /* The domain is inaccessible during the next snapshot. Its old
       saved value must not be used if it becomes accessible on resume. */
    seq[0].condition=0;
    seq[0].reg=99;
    seq[0].need_skip=true;
    seq[1].reg=21;
    pmucal_rae_save_seq(seq,5);
    assert(reads==5 && seq[0].value==10);
    assert(!seq[0].need_restore && !seq[0].need_skip);
    assert(seq[1].need_restore && seq[1].value==21);
    seq[0].condition=1;
    pmucal_rae_save_seq(seq,5);
    assert(seq[0].need_restore && seq[0].value==99);
    return 0;
}
'''
        with tempfile.TemporaryDirectory() as tmp:
            src, exe = Path(tmp)/"snapshot.c", Path(tmp)/"snapshot"
            src.write_text(harness)
            subprocess.run(["cc","-std=gnu11","-Wall","-Wextra","-Werror",
                            "-Wno-sign-compare","-Wno-implicit-fallthrough",
                            str(src),"-o",str(exe)],check=True,timeout=15)
            subprocess.run([str(exe)],check=True,timeout=5)

    def test_kernel_patch_format(self):
        subprocess.run(["git","apply","--numstat","src/kernel/r800-wearos.patch"],
                       cwd=ROOT,capture_output=True,check=True,timeout=10)


if __name__ == "__main__":
    unittest.main()
