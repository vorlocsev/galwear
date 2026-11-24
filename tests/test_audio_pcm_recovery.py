"""Source guards for PCM route failure and bounded XRUN recovery policy."""
from pathlib import Path
import unittest

SOURCE = Path(__file__).resolve().parents[1] / "src/hal/audio_r800.c"


class AudioPcmRecoveryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = SOURCE.read_text()

    def function(self, start, end):
        return self.source.split(start, 1)[1].split(end, 1)[0]

    def test_tinyalsa_auto_restart_disabled_on_both_streams(self):
        self.assertIn("PCM_OUT | PCM_MONOTONIC | PCM_NORESTART", self.source)
        self.assertIn("PCM_IN | PCM_MONOTONIC | PCM_NORESTART", self.source)

    def test_speaker_route_failure_stops_before_pcm_open(self):
        s = self.function("static int start_output(", "static ssize_t out_write(")
        self.assertIn("if (apply_mixer(spk_on,", s)
        self.assertLess(s.index("apply_mixer(spk_off,"), s.index("pcm_open(CARD"))
        self.assertLess(s.index("return -EIO;"), s.index("pcm_open(CARD"))

    def test_microphone_route_failure_stops_before_pcm_open(self):
        s = self.function("static int start_input(", "static ssize_t in_read(")
        self.assertIn("if (apply_mixer(mic_on,", s)
        self.assertLess(s.index("apply_mixer(mic_off,"), s.index("pcm_open(CARD"))
        self.assertLess(s.index("return -EIO;"), s.index("pcm_open(CARD"))

    def test_failed_transfers_close_and_back_off(self):
        out = self.function("static ssize_t out_write(", "static int out_get_render_position(")
        inp = self.function("static ssize_t in_read(", "static int in_get_capture_position(")
        self.assertIn("do_standby(out);\n            out->next_open_ns = now_ns() + RETRY_NS;", out)
        self.assertIn("in_do_standby(in);\n            in->next_open_ns = now_ns() + RETRY_NS;", inp)

    def test_reject_unrepresentable_or_null_transfer(self):
        self.assertEqual(self.source.count("bytes > SSIZE_MAX || (bytes && !buf)"), 2)


if __name__ == "__main__":
    unittest.main()
