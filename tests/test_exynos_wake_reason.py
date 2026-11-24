"""Exercise the actual Exynos EINT wake-reason decoder with synthetic PMU/GPIO."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class ExynosWakeReasonTests(unittest.TestCase):
    def test_actual_eint_decoder(self):
        patch = (ROOT / "src/kernel/r800-wearos.patch").read_text()
        section = patch.split("diff --git a/drivers/soc/samsung/exynos-pm.c ", 1)[1].split("diff --git ", 1)[0]
        code = "\n".join(line[1:] for line in section.splitlines()
                         if line.startswith((" ", "+")) and not line.startswith("+++"))
        helper = code[code.index("static void exynos_show_wakeup_reason_eint("):
                      code.index("static void exynos_show_wakeup_registers(")]
        harness = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#define CONFIG_SUSPEND 1
#define EXYNOS_PM_PREFIX "test"
#define EXYNOS_PMU_EINT_WAKEUP_MASK 0x60c
#define BIT(i) (1UL<<(i))
#define EXYNOS_EINT_PEND(b,x) (x)
#define for_each_set_bit(bit,addr,size) for ((bit)=0;(bit)<(size);(bit)++) if (*(addr)&BIT(bit))
#define pr_warn(...) ((void)0)
#define pr_info(...) ((void)0)
typedef uint32_t u32;
static struct {unsigned int num_eint; int eint_base;} info={13,0}, *pm_info=&info;
static unsigned int mask;
static int read_error, reads, maps, count, irqs[64], invalid=-1;
static unsigned long pending[8];
static int exynos_pmu_read(unsigned int reg,unsigned int *val) {
    (void)reg; if(read_error)return -1; *val=mask; return 0;
}
static unsigned long __raw_readl(int index){reads++;return pending[index/8];}
static u32 exynos_eint_to_pin_num(int pin){maps++;return pin;}
static int gpio_to_irq(u32 gpio){return (int)gpio==invalid?-22:100+(int)gpio;}
static void log_irq_wakeup_reason(int irq){irqs[count++]=irq;}
''' + helper + r'''
int main(void){
    pending[0]=BIT(1)|BIT(3);
    pending[1]=BIT(4)|BIT(5)|BIT(7);
    mask=BIT(3);
    exynos_show_wakeup_reason_eint();
    assert(reads==2 && maps==2 && count==2 && irqs[0]==101 && irqs[1]==112);
    invalid=12;
    count=maps=reads=0;
    exynos_show_wakeup_reason_eint();
    assert(count==1 && irqs[0]==101 && maps==2);
    read_error=1;count=maps=reads=0;
    exynos_show_wakeup_reason_eint();
    assert(!reads && !maps && !count);
    read_error=0;info.num_eint=40;invalid=-1;
    pending[4]=BIT(0);
    exynos_show_wakeup_reason_eint();
    assert(count==4 && irqs[3]==115);
    return 0;
}
'''
        with tempfile.TemporaryDirectory() as tmp:
            src, exe = Path(tmp)/"wake.c", Path(tmp)/"wake"
            src.write_text(harness)
            subprocess.run(["cc","-std=gnu11","-Wall","-Wextra","-Werror",
                            "-Wno-sign-compare",str(src),"-o",str(exe)],check=True,timeout=15)
            subprocess.run([str(exe)],check=True,timeout=5)

    def test_pmu_read_failures_not_reported_as_wakeup(self):
        patch = (ROOT / "src/kernel/r800-wearos.patch").read_text()
        self.assertIn("+\tif (exynos_pmu_read(EXYNOS_PMU_WAKEUP_STAT, &wakeup_stat))",patch)
        self.assertIn("extra wake status %d unavailable",patch)
        self.assertIn("EINT wake mask unavailable",patch)

    def test_dts_reports_thirteen_eint_sources(self):
        dts = (ROOT / "src/dt/r800.dts").read_text()
        self.assertIn("num-eint = <0x0d>;",dts)
        self.assertIn("eint_wakeup_mask_offset = <0x60c>;",dts)


if __name__ == "__main__":
    unittest.main()
