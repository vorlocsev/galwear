"""Exercise the actual Runtime PM reference-balance hunk with a host C fixture."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
PATCH = ROOT / "src/kernel/r800-wearos.patch"


class MaliRuntimePmTests(unittest.TestCase):
    def test_actual_get_sync_reference_balance(self):
        patch = PATCH.read_text()
        section = patch.split("diff --git a/drivers/gpu/arm/t72x/r28p0/platform/exynos/gpu_notifier.c ", 1)[1].split("diff --git ", 1)[0]
        lines = section.splitlines()
        start = next(i for i, line in enumerate(lines) if line.startswith("@@ "))
        body = "\n".join(line[1:] for line in lines[start + 1:] if line.startswith((" ", "+")))
        body = body.split("#ifdef CONFIG_MALI_RT_PM", 1)[1].split("#else", 1)[0]
        harness = r'''
#include <assert.h>
#include <stdbool.h>
struct device {int usage, result;};
struct kbase_device {struct device *dev;bool is_power_on;};
static int pm_runtime_get_sync(struct device *d){d->usage++;return d->result;}
static void pm_runtime_put_noidle(struct device *d){d->usage--;}
static int power_on(struct kbase_device *kbdev){
    int ret=0;
''' + body + r'''
    return ret;
}
int main(void){
    struct device d={0,-5};
    struct kbase_device k={&d,false};
    assert(power_on(&k)==-5 && d.usage==0 && !k.is_power_on);
    assert(power_on(&k)==-5 && d.usage==0 && !k.is_power_on);
    d.result=0;
    assert(power_on(&k)==0 && d.usage==1 && k.is_power_on);
    assert(power_on(&k)==0 && d.usage==1);
    k.is_power_on=false; d.usage=0; d.result=1;
    assert(power_on(&k)==1 && d.usage==1 && k.is_power_on);
    return 0;
}
'''
        with tempfile.TemporaryDirectory() as tmp:
            src, exe = Path(tmp)/"pm.c", Path(tmp)/"pm"
            src.write_text(harness)
            subprocess.run(["cc","-std=c11","-Wall","-Wextra","-Werror",str(src),"-o",str(exe)],
                           check=True,timeout=15)
            subprocess.run([str(exe)],check=True,timeout=5)

    def test_patch_format(self):
        subprocess.run(["git","apply","--numstat",str(PATCH)],cwd=ROOT,
                       capture_output=True,check=True,timeout=10)

    def test_sleep_guard_retained(self):
        helper = (ROOT / "payload/android-helper.sh").read_text()
        self.assertIn('if [ -f "$SLEEPF" ]; then',helper)
        self.assertIn("echo r800helper > /sys/power/wake_lock",helper)


if __name__ == "__main__":
    unittest.main()
