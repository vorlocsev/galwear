"""Host fixture of the added Exynos PMU/PSCI transaction logic."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class ExynosPmRecoveryTests(unittest.TestCase):
    def test_actual_prepare_and_resume(self):
        patch = (ROOT / "src/kernel/r800-wearos.patch").read_text()
        section = patch.split("diff --git a/drivers/soc/samsung/exynos-pm.c ", 1)[1].split("diff --git ", 1)[0]
        code = "\n".join(line[1:] for line in section.splitlines()
                         if line.startswith((" ", "+")) and not line.startswith("+++"))
        # Hunks omit unchanged lines between sections. Extract the contiguous
        # transition logic from its first assignment through resume.
        start = code.index("pm_info->prepared_mode =")
        end = code.index("static struct syscore_ops exynos_pm_syscore_ops", start)
        transaction = code[start:end]
        harness = r'''
#include <assert.h>
#include <stdbool.h>
#include <errno.h>
#define NUM_SYS_POWERDOWN 12
#define EXYNOS_PM_PREFIX "test"
#define pr_err(...) ((void)0)
#define pr_info(...) ((void)0)
#define R800_MARK(n) ((void)(n))
static struct {
    bool is_usbl2_suspend,is_early_wakeup,prepared,recovery_failed;
    unsigned int prepared_mode,usbl2_suspend_mode_idx,suspend_mode_idx;
} info, *pm_info=&info;
static struct { int test_usbl2_suspend; } dbg, *pm_dbg=&dbg;
static int prepare_error, recovery_error, prepare_calls, resume_calls, resume_mode;
static bool resume_early;
static int exynos_prepare_sys_powerdown(unsigned int mode) {
    (void)mode; prepare_calls++; return prepare_error;
}
static int exynos_wakeup_sys_powerdown_checked(unsigned int mode,bool early) {
    resume_calls++;resume_mode=mode;resume_early=early;
    return recovery_error;
}
static void exynos_show_wakeup_reason(bool early){(void)early;}
static int prepare(void){
    int ret;
    if (pm_info->recovery_failed) return -EIO;
    pm_info->is_early_wakeup=true;
    pm_info->prepared=false;
''' + transaction + r'''
int main(void){
    info.suspend_mode_idx=8;info.usbl2_suspend_mode_idx=9;
    assert(!prepare() && info.prepared && info.is_early_wakeup);
    dbg.test_usbl2_suspend=1;
    exynos_pm_syscore_resume();
    assert(resume_calls==1 && resume_mode==8 && resume_early && !info.prepared);
    exynos_pm_syscore_resume();
    assert(resume_calls==1);
    assert(!prepare() && info.prepared_mode==9);
    info.is_early_wakeup=false;
    exynos_pm_syscore_resume();
    assert(resume_calls==2 && resume_mode==9 && !resume_early);
    prepare_error=-EIO;
    assert(prepare()==-EIO && !info.prepared);
    assert(resume_calls==3 && resume_early);
    dbg.test_usbl2_suspend=0;info.suspend_mode_idx=99;
    assert(prepare()==-EINVAL && prepare_calls==3);
    info.suspend_mode_idx=8;prepare_error=0;
    assert(!prepare());
    recovery_error=-ETIMEDOUT;
    exynos_pm_syscore_resume();
    assert(info.recovery_failed && !info.prepared);
    assert(prepare()==-EIO && prepare_calls==4);
    /* An independent trial: failed preparation and failed rollback. */
    info.recovery_failed=false;prepare_error=-EBUSY;
    assert(prepare()==-EBUSY && info.recovery_failed);
    assert(prepare()==-EIO && prepare_calls==5);
    return 0;
}
'''
        with tempfile.TemporaryDirectory() as tmp:
            src, exe = Path(tmp)/"pm.c", Path(tmp)/"pm"
            src.write_text(harness)
            subprocess.run(["cc","-std=gnu11","-Wall","-Wextra","-Werror",
                            str(src),"-o",str(exe)],check=True,timeout=15)
            subprocess.run([str(exe)],check=True,timeout=5)

    def test_psci_errno_preserved(self):
        patch = (ROOT / "src/kernel/r800-wearos.patch").read_text()
        self.assertIn("+\tret = arm_cpuidle_suspend(psci_index);", patch)
        self.assertIn("+\tpm_info->is_early_wakeup = ret != 0;", patch)
        self.assertIn("+\t\treturn ret < 0 ? ret : -EBUSY;", patch)
        self.assertIn("+\tpm_info->is_early_wakeup = true;", patch)

    def test_recovery_interlock_and_markers(self):
        patch = (ROOT / "src/kernel/r800-wearos.patch").read_text()
        self.assertIn("+\tif (pm_info->recovery_failed)", patch)
        self.assertIn("R800_MARK(0x11);", patch)
        self.assertIn("R800_MARK(0x12);", patch)
        self.assertIn("ret = cal_pm_earlywakeup(mode);", patch)
        self.assertIn("ret = cal_pm_exit(mode);", patch)

    def test_patch_format(self):
        subprocess.run(["git","apply","--numstat","src/kernel/r800-wearos.patch"],
                       cwd=ROOT,capture_output=True,check=True,timeout=10)


if __name__ == "__main__":
    unittest.main()
