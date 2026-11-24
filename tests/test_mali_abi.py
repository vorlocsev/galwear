"""Host checks for selected R28P0 ioctl ABI assertions and dispatch inspection."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "build"))
import r800_mali_abi_check as abi


def fixture():
    return "\n".join("case KBASE_IOCTL_" + n + ":" for n in abi.OPS) + """
.unlocked_ioctl = kbase_ioctl,
.compat_ioctl = kbase_ioctl,
static int kbase_api_stream_create(int x)
{
#if defined(CONFIG_SYNC) || defined(CONFIG_SYNC_FILE)
    return 0;
#endif
}
static int kbase_api_fence_validate(int x)
{
#if defined(CONFIG_SYNC) || defined(CONFIG_SYNC_FILE)
    return 0;
#endif
}
"""


class MaliAbiTests(unittest.TestCase):
    def test_known_ioctl_numbers(self):
        self.assertEqual(abi.command(3,0,4),0xc0048000)
        self.assertEqual(abi.command(1,2,16),0x40108002)
        self.assertEqual(abi.command(3,22,24),0xc0188016)

    def test_assertions_include_layout_and_original_header(self):
        unit = abi.source_unit()
        self.assertIn('#include "mali_kbase_ioctl.h"',unit)
        self.assertIn("BASE_UK_VERSION_MINOR == 13",unit)
        for name in abi.OPS:
            self.assertIn("KBASE_IOCTL_" + name + " ==",unit)
        self.assertIn("offsetof(union kbase_ioctl_mem_import, in.phandle) == 8",unit)

    def test_valid_dispatch(self):
        abi.check_dispatch(fixture())

    def test_missing_case(self):
        with self.assertRaisesRegex(ValueError,"JOB_SUBMIT"):
            abi.check_dispatch(fixture().replace("case KBASE_IOCTL_JOB_SUBMIT:", "/* case KBASE_IOCTL_JOB_SUBMIT: */"))

    def test_wrong_compat_handler(self):
        with self.assertRaisesRegex(ValueError,"compat_ioctl"):
            abi.check_dispatch(fixture().replace(".compat_ioctl = kbase_ioctl,", ".compat_ioctl = other,"))

    def test_wrong_sync_gate(self):
        with self.assertRaisesRegex(ValueError,"fence configuration gate"):
            abi.check_dispatch(fixture().replace("defined(CONFIG_SYNC_FILE)", "defined(CONFIG_MALI_DMA_FENCE)"))


if __name__ == "__main__":
    unittest.main()
