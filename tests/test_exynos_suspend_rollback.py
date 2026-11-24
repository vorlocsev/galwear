"""Host fixture of the actual experimental Exynos power-domain transaction."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class ExynosSuspendRollbackTests(unittest.TestCase):
    def test_actual_suspend_and_rollback(self):
        patch = (ROOT / "src/kernel/r800-wearos.patch").read_text()
        section = patch.split("diff --git a/drivers/soc/samsung/exynos-pd.c ", 1)[1].split("diff --git ", 1)[0]
        code = "\n".join(l[1:] for l in section.splitlines() if l.startswith("+") and not l.startswith("+++"))
        helpers = code[code.index("static int r800_pd_restore("):code.index("/*\n * Live test:")]
        core = code[code.index("static int r800_pd_unwind("):code.index("static struct syscore_ops")]
        harness = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <errno.h>
#include <stddef.h>
#define BIT(i) (1U<<(i))
#define ARRAY_SIZE(x) (sizeof(x)/sizeof((x)[0]))
#define pr_err(...) ((void)0)
#define pr_info(...) ((void)0)
typedef uint32_t u32;
struct exynos_pm_domain {int cal_pdid;const char *name;};
static struct exynos_pm_domain pds[]={{0,"is"},{1,"vts"},{2,"g3d"},{3,"dispaud"}};
static struct exynos_pm_domain *r800_sleep_pd[]={&pds[0],&pds[1],&pds[2]};
static struct exynos_pm_domain *r800_dispaud=&pds[3];
static bool r800_sleep_pd_was_on[3],r800_dispaud_was_on;
static unsigned int r800_sleep_pd_off=3;
static bool r800_dispaud_sleep_off=true,r800_dispaud_clr_b31=false;
static unsigned char *r800_cmu_dispaud;
static u32 r800_ctrl_opt_saved;
#define R800_CTRL_OPT 0x800
static int state[]={1,1,0,1}, history[32], count, fail_off=-1, fail_on=-1, abox;
static int cal_pd_status(int id){return state[id];}
static int cal_pd_control(int id,int on){
    history[count++]=on?10+id:id;
    if(on && id==fail_on)return -EIO;
    state[id]=on;
    return !on && id==fail_off?-EIO:0;
}
static int abox_is_on(void){return abox;}
static u32 readl(void *p){(void)p;return 0;}
static void writel(u32 v,void *p){(void)v;(void)p;}
static int r800_ctrl_opt_restore(void){return 0;}
''' + helpers + core + r'''
int main(void){
    abox=1;
    assert(r800_pd_syscore_suspend()==-EBUSY && count==0);
    abox=0;state[1]=-EIO;
    assert(r800_pd_syscore_suspend()==-EIO && count==0);
    state[1]=1;fail_off=1;
    assert(r800_pd_syscore_suspend()==-EIO);
    assert(count==4 && history[0]==0 && history[1]==1 && history[2]==11 && history[3]==10);
    assert(state[0]==1 && state[1]==1 && !r800_sleep_pd_was_on[0]);
    fail_off=-1;count=0;
    assert(!r800_pd_syscore_suspend());
    assert(count==3 && history[2]==3);
    r800_pd_syscore_resume();
    assert(count==6 && history[3]==13 && history[4]==11 && history[5]==10);
    assert(!r800_dispaud_was_on);
    count=0;fail_off=1;fail_on=1;
    assert(r800_pd_syscore_suspend()==-EIO);
    assert(r800_sleep_pd_was_on[1] && !r800_sleep_pd_was_on[0]);
    assert(r800_pd_syscore_suspend()==-EBUSY);
    return 0;
}
'''
        with tempfile.TemporaryDirectory() as tmp:
            src, exe = Path(tmp)/"pd.c", Path(tmp)/"pd"
            src.write_text(harness)
            subprocess.run(["cc","-std=gnu11","-Wall","-Wextra","-Werror",
                            "-Wno-sign-compare",str(src),"-o",str(exe)],check=True,timeout=15)
            subprocess.run([str(exe)],check=True,timeout=5)

    def test_patch_format(self):
        subprocess.run(["git","apply","--numstat","src/kernel/r800-wearos.patch"],
                       cwd=ROOT,capture_output=True,check=True,timeout=10)

    def test_default_sleep_opt_in_unchanged(self):
        helper = (ROOT / "payload/android-helper.sh").read_text()
        self.assertIn('if [ -f "$SLEEPF" ]; then',helper)
        self.assertIn("echo r800helper > /sys/power/wake_lock",helper)


if __name__ == "__main__":
    unittest.main()
