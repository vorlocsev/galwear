"""Synthetic tests for ART probe paths and namespace construction."""
import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"build"))
import r800_wear51_art_probe as probe

def objects():
    names={probe.LINKER:"ld-android.so",probe.DEX:None,probe.STUB:"ld-android.so",
           "runtime:/lib/bionic/libc.so":"libc.so","runtime:/lib/bionic/libm.so":"libm.so",
           "runtime:/lib/bionic/libdl.so":"libdl.so","art:/lib/libbase.so":"libbase.so",
           "system:/system/lib/libbase.so":"libbase.so","statsd:/lib/libstatspull.so":"libstatspull.so",
           "statsd:/lib/libstatssocket.so":"libstatssocket.so"}
    return {k:{"soname":v} for k,v in names.items()}

class ArtProbeTests(unittest.TestCase):
    def test_separate_locations(self):
        self.assertEqual(probe.guest_path("art:/lib/libbase.so"),"/apex/com.android.art/lib/libbase.so")
        self.assertEqual(probe.guest_path("system:/system/lib/libbase.so"),"/system/lib/libbase.so")

    def test_reject_paths(self):
        for key in ("host:/lib/a.so","art:/lib/../a.so","system:/lib/a.so","runtime:/bin/evil.so"):
            with self.subTest(key=key),self.assertRaises(ValueError):
                probe.guest_path(key)

    def test_config_preserves_namespaces(self):
        cfg=probe.config(objects())
        self.assertIn("namespace.default.search.paths = /apex/com.android.art/lib\n",cfg)
        self.assertIn("namespace.system.search.paths = /system/lib\n",cfg)
        self.assertIn("namespace.default.link.statsd.shared_libs = libstatspull.so:libstatssocket.so\n",cfg)
        self.assertIn("namespace.default.link.system.shared_libs = libbase.so\n",cfg)
        self.assertNotIn("allow_all_shared_libs",cfg)

    def test_missing_statsd(self):
        data=objects()
        del data["statsd:/lib/libstatspull.so"]
        with self.assertRaisesRegex(ValueError,"StatsD"):
            probe.config(data)

if __name__=="__main__":
    unittest.main()
