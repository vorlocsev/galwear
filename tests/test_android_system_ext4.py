"""Synthetic labeled EXT4 fixture contracts; no actual e2fsdroid execution."""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/"build"))
import r800_android_system_ext4 as a

def fixture():
    return [
        ("system", (0o040755, b"", 0, 0)),
        ("system/bin", (0o040755, b"", 0, 0)),
        ("system/bin/galwear_property_service", (0o100755, b"service", 0, 0)),
        ("system/bin/galwear_property_client", (0o100755, b"client", 0, 0)),
        ("system/bin/linker64", (0o120777, b"/apex/com.android.runtime/bin/linker64", 0, 0)),
        ("apex", (0o040755, b"", 0, 0)),
        ("init", (0o100755, b"probe", 0, 0)),
    ]

class SystemExt4Tests(unittest.TestCase):
    def test_only_system_entries(self):
        r = a.system_entries(fixture(), {a.FILE_CONTEXTS[0]: b"contexts"})
        self.assertIn(a.FILE_CONTEXTS[0], r)
        self.assertIn("system/etc/selinux", r)
        self.assertNotIn("apex", r)
        self.assertNotIn("init", r)

    def test_reject_wrong_link_target(self):
        entries = fixture()
        entries[4] = (entries[4][0], (0o120777, b"/etc/passwd", 0, 0))
        with self.assertRaisesRegex(ValueError, "Unsupported system symlink"):
            a.system_entries(entries, {})

    def test_reject_device_node(self):
        with self.assertRaisesRegex(ValueError, "inode type"):
            a.system_entries(fixture()+[("system/dev", (0o060600, b"", 1, 2))], {})

    def test_reject_traversal(self):
        with self.assertRaisesRegex(ValueError, "Unexpected system"):
            a.system_entries(fixture()+[("system/../evil", (0o100644, b"x", 0, 0))], {})

    def test_relative_alias(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            a.materialize(root, a.system_entries(fixture(), {}))
            link = root/"system/bin/linker64"
            self.assertEqual(str(link.readlink()), "../../apex/com.android.runtime/bin/linker64")
            self.assertTrue(link.resolve().is_relative_to(root))

    def test_expected_context_uses_guest_path_and_mode(self):
        with patch.object(a, "invoke", return_value=subprocess.CompletedProcess([], 0, stdout=b"u:object_r:init_exec:s0\n")) as run:
            self.assertEqual(a.expected_label("contexts", "system/bin/init", 0o100755, "matchpathcon"),
                             "u:object_r:init_exec:s0")
        self.assertEqual(run.call_args.args[0], ["matchpathcon","-N","-n","-f","contexts","-m","f","/system/bin/init"])

    def test_missing_context_rejected(self):
        with patch.object(a, "invoke", return_value=subprocess.CompletedProcess([], 0, stdout=b"<<none>>\n")):
            with self.assertRaisesRegex(ValueError, "expected context"):
                a.expected_label("contexts", "system/bin/init", 0o100755, "matchpathcon")

    def test_canned_root_and_exact_modes(self):
        config = a.canned_config(a.system_entries(fixture(), {}), "system")
        self.assertIn(b"/ 0 0 0755 capabilities=0\n", config)
        self.assertIn(b"system/bin/linker64 0 0 0777 capabilities=0\n", config)
        self.assertIn(b"system/bin/galwear_property_service 0 0 0755 capabilities=0\n", config)

    def test_reject_special_mode_bits(self):
        entries = {"system": (0o040755,b"",0,0),
                   "system/bin": (0o042755,b"",0,0)}
        with self.assertRaisesRegex(ValueError,"Invalid canned"):
            a.canned_config(entries,"system")

    def test_readback_label_and_payload(self):
        with tempfile.TemporaryDirectory() as tmp:
            scratch = Path(tmp)
            label = "u:object_r:init_exec:s0"
            def mock(args):
                command = args[2]
                if command.startswith("stat "):
                    return subprocess.CompletedProcess([], 0, stdout=b"Inode: 12 Type: regular Mode: 0755\nUser: 0 Group: 0 Size: 6\n")
                if command.startswith("ea_get "):
                    (scratch/"label").write_bytes(label.encode()+b"\0")
                elif command.startswith("dump "):
                    (scratch/"payload").write_bytes(b"binary")
                return subprocess.CompletedProcess([], 0, stdout=b"")
            with patch.object(a, "invoke", side_effect=mock):
                item = (0o100755,b"binary",0,0)
                r = a.inspect_inode("image", "system/bin/init", item, label, scratch, "debugfs")
                self.assertEqual(r["sha256"], a.sha(b"binary"))
                with self.assertRaisesRegex(ValueError, "xattr mismatch"):
                    a.inspect_inode("image", "system/bin/init", item, "u:object_r:system_file:s0", scratch, "debugfs")

if __name__ == "__main__":
    unittest.main()
