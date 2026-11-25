"""Check lock hierarchy and scope in actual Audio HAL source."""
from pathlib import Path
import unittest

SOURCE = Path(__file__).resolve().parents[1] / "src/hal/audio_r800.c"


class AudioRouteLockTests(unittest.TestCase):
    def test_media_route_transactions_not_pcm_io(self):
        s = SOURCE.read_text()
        for name, stream in (("start_output", "out"), ("start_input", "in")):
            b = s[s.index("static int " + name + "("):]
            b = b[:b.index("\n}\n")]
            lock = "pthread_mutex_lock(&" + stream + "->adev->route_lock);"
            unlock = "pthread_mutex_unlock(&" + stream + "->adev->route_lock);"
            self.assertLess(b.index(lock), b.index("apply_mixer("))
            self.assertLess(b.index("pcm_open("), b.index(unlock))
            self.assertEqual(b.count(unlock), 2)
            self.assertLess(b.index("fail:"), b.rindex(unlock))
        for name in ("out_write", "in_read"):
            b = s[s.index("static ssize_t " + name + "("):]
            b = b[:b.index("\n}\n")]
            self.assertNotIn("route_lock", b)

    def test_hfp_locks_after_media_standby_and_unlocks_before_rollback(self):
        s = SOURCE.read_text()
        b = s[s.index("static int hfp_start("):]
        b = b[:b.index("\n}\n")]
        self.assertLess(b.index("in_do_standby("), b.index("pthread_mutex_lock(&adev->route_lock)"))
        self.assertLess(b.index("pthread_mutex_lock(&adev->in->lock)"), b.index("pthread_mutex_lock(&adev->route_lock)"))
        fail = b[b.index("fail:"):]
        self.assertLess(fail.index("pthread_mutex_unlock(&adev->route_lock)"), fail.index("hfp_stop(adev)"))


if __name__ == "__main__":
    unittest.main()
