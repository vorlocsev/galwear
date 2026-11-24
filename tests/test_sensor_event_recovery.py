"""Compile actual SSP mask and evdev overrun helpers with host-only fixtures."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src/hal/sensors_r800.c"


class SensorRecoveryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = SOURCE.read_text()
        s = cls.source
        mask = s[s.index("static int parse_enable_mask("):s.index("static int read_enable_mask(")]
        overrun = s[s.index("static int discard_overrun("):s.index("static int dev_poll(")]
        harness = r'''
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <linux/input.h>
struct hub_sensor { int32_t v[6]; uint16_t ts[4]; int dropped; };
''' + mask + overrun + r'''
int main(int argc, char **argv) {
    if (argc == 2) {
        long long value = -1;
        int r = parse_enable_mask(argv[1], &value);
        if (r) { assert(value == -1); return 1; }
        assert(value >= 0);
        return 0;
    }
    struct hub_sensor s = {.v={11,22}, .ts={1,2}};
    struct input_event ev = {.type=EV_SYN,.code=SYN_DROPPED};
    assert(discard_overrun(&s,&ev) == 1 && s.dropped);
    assert(s.v[0] == 0 && s.v[1] == 0 && s.ts[0] == 0);
    ev.type=EV_REL; ev.code=REL_X;
    assert(discard_overrun(&s,&ev) == 1);
    ev.type=EV_SYN; ev.code=SYN_REPORT;
    assert(discard_overrun(&s,&ev) == 1 && !s.dropped);
    ev.type=EV_REL; ev.code=REL_X;
    assert(discard_overrun(&s,&ev) == 0);
    return 0;
}
'''
        cls.tmp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.tmp.cleanup)
        src = Path(cls.tmp.name) / "fixture.c"
        cls.exe = Path(cls.tmp.name) / "fixture"
        src.write_text(harness)
        subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                        str(src), "-o", str(cls.exe)], check=True, timeout=15)

    def test_valid_masks(self):
        for value in ("0", "262144", "1048576\n", "9223372036854775807"):
            with self.subTest(value=value):
                subprocess.run([str(self.exe), value], check=True, timeout=5)

    def test_bad_masks_rejected(self):
        for value in ("", "-1", "+2", "1x", " 1", "1\n2", "9223372036854775808"):
            with self.subTest(value=value):
                self.assertEqual(subprocess.run([str(self.exe), value], timeout=5).returncode, 1)

    def test_syn_dropped_recovery(self):
        subprocess.run([str(self.exe)], check=True, timeout=5)

    def test_mask_write_is_guarded(self):
        self.assertIn("int r = read_enable_mask(&current);", self.source)
        self.assertIn("(current & ~ours) | want", self.source)
        self.assertIn("refusing write", self.source)

    def test_short_write_is_error(self):
        self.assertIn("written < 0 ? -errno : -EIO", self.source)

    def test_enable_state_rollback(self):
        self.assertIn("hub[handle].enabled = previous;", self.source)
        self.assertIn("hub[H_HR].enabled = previous;", self.source)

    def test_no_batch_discard(self):
        self.assertIn("struct input_event ie[1];", self.source)
        self.assertNotIn("struct input_event ie[32];", self.source)

    def test_poll_failure_and_capacity_guards(self):
        self.assertIn("if (!data || count <= 0)", self.source)
        self.assertIn("POLLERR | POLLHUP | POLLNVAL", self.source)


if __name__ == "__main__":
    unittest.main()
