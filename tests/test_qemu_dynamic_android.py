"""Synthetic dynamic initramfs and guest console contracts."""
from pathlib import Path
import json
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "build"))
import r800_qemu_dynamic_android as a

LOG = (a.EXPECTED + a.DYNAMIC_MARKER + b"\n" + a.CHILD_MARKER + b"\n"
       + a.HEARTBEAT_PREFIX + b"00000001\n")


def entries():
    result = [(name, 0o040755, b"", 0, 0) for name in a.DIRS]
    result += [("dev/console", 0o020600, b"", 5, 1),
               ("init", 0o100755, b"init", 0, 0),
               (a.PROBE_PATH, 0o100755, b"probe", 0, 0),
               (a.LINKER_PATH, 0o100755, b"linker", 0, 0),
               ("system/bin/linker64", 0o120777, a.ALIAS.encode(), 0, 0),
               ("linkerconfig/ld.config.txt", 0o100644, a.CONFIG, 0, 0)]
    result += [(a.RUNTIME + "/lib64/bionic/" + name, 0o100644, b"library", 0, 0)
               for name in a.LIBS]
    return result


class DynamicBootTests(unittest.TestCase):
    def test_deterministic_newc_and_header_contents(self):
        fixture = entries()
        raw = a.newc(fixture)
        self.assertEqual(raw, a.newc(fixture))
        pos = 0
        for name, mode, data, major, minor in fixture + [("TRAILER!!!", 0, b"", 0, 0)]:
            self.assertEqual(raw[pos:pos+6], b"070701")
            fields = [int(raw[pos+6+i*8:pos+14+i*8], 16) for i in range(13)]
            self.assertEqual(fields[1], mode)
            self.assertEqual(fields[2:4], [0, 0])
            self.assertEqual(fields[9:11], [major, minor])
            self.assertEqual(fields[6], len(data))
            start = pos + 110
            end = start + fields[11]
            self.assertEqual(raw[start:end], name.encode() + b"\0")
            payload = (end + 3) & ~3
            self.assertEqual(raw[payload:payload+len(data)], data)
            pos = (payload + len(data) + 3) & ~3
        self.assertEqual(pos, len(raw))

    def test_missing_and_duplicate_entry_rejected(self):
        fixture = entries()
        for invalid in (fixture[:-1], fixture[:-1] + [fixture[0]]):
            with self.assertRaisesRegex(ValueError, "entry set"):
                a.newc(invalid)

    def test_wrong_device_or_linker_alias_rejected(self):
        fixture = entries()
        for name, value in (("dev/console", ("dev/console", 0o020600, b"", 8, 0)),
                            ("system/bin/linker64", ("system/bin/linker64", 0o120777, b"/host", 0, 0))):
            with self.assertRaisesRegex(ValueError, "mode or payload"):
                a.newc([value if entry[0] == name else entry for entry in fixture])

    def test_missing_parent_rejected(self):
        fixture = entries()
        child = next(e for e in fixture if e[0] == a.PROBE_PATH)
        fixture.remove(child)
        with self.assertRaisesRegex(ValueError, "parent"):
            a.newc([child] + fixture)

    def test_dynamic_markers(self):
        self.assertTrue(a.inspect_dynamic(LOG)["dynamic_android_linker_tested"])
        for marker in (a.DYNAMIC_MARKER, a.CHILD_MARKER):
            with self.assertRaisesRegex(ValueError, "Missing"):
                a.inspect_dynamic(LOG.replace(marker, b""))

    def test_early_heartbeat(self):
        with self.assertRaisesRegex(ValueError, "Heartbeat before"):
            a.inspect_dynamic(LOG.replace(a.CHILD_MARKER + b"\n", b"") + a.CHILD_MARKER + b"\n")

    def test_same_kernel_baseline(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "evidence.json"
            baseline = {"status": "VIRT_GUEST_BIONIC_ABI_ONLY",
                        "generic_kernel_sha256": "kernel", "bionic_tested": True,
                        "guest_kernel_syscalls_tested": True, "safe_to_flash": False}
            p.write_text(json.dumps(baseline))
            a.verify_baseline(p, "kernel")
            for key, value in (("bionic_tested", False), ("generic_kernel_sha256", "wrong")):
                p.write_text(json.dumps({**baseline, key: value}))
                with self.assertRaisesRegex(ValueError, "baseline"):
                    a.verify_baseline(p, "kernel")

    def test_snapshot_digest(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "file"
            p.write_bytes(b"file")
            self.assertEqual(a.snapshot(p, a.sha(b"file")), b"file")
            with self.assertRaisesRegex(ValueError, "digest mismatch"):
                a.snapshot(p, a.sha(b"other"))


if __name__ == "__main__":
    unittest.main()
