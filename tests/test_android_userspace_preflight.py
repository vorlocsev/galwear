"""Offline fixtures only: no Android binary execution or physical watch."""
import os
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "build"))
import r800_android_userspace_preflight as audit


def elf64(machine=183, interp=None):
    data = bytearray(256)
    data[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HH", data, 16, 2, machine)
    struct.pack_into("<QQ", data, 24, 0x400000, 64)
    struct.pack_into("<HH", data, 54, 56, 2 if interp else 1)
    struct.pack_into("<IIQQQQQQ", data, 64, 1, 5, 0, 0x400000, 0, 256, 256, 4096)
    if interp:
        raw = interp.encode() + b"\0"
        struct.pack_into("<IIQQQQQQ", data, 120, 3, 4, 192, 0, 0, len(raw), len(raw), 1)
        data[192:192+len(raw)] = raw
    return data


def elf32():
    data = bytearray(128)
    data[:7] = b"\x7fELF\x01\x01\x01"
    struct.pack_into("<HH", data, 16, 2, 40)
    struct.pack_into("<II", data, 24, 0x10000, 52)
    struct.pack_into("<HH", data, 42, 32, 1)
    struct.pack_into("<IIIIIIII", data, 52, 1, 0, 0x10000, 0, 128, 128, 5, 4096)
    return data


class UserspaceTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name) / "root"
        self.root.mkdir()
        self.config = Path(temp.name) / "config"
        self.config.write_text("".join(f"{k}={v}\n" for k, v in audit.REQUIRED_CONFIG.items()))
        for name in ("init", "system/bin/servicemanager", "system/bin/hwservicemanager",
                     "vendor/bin/vndservicemanager", "system/bin/app_process32"):
            self.put(name, elf32() if name.endswith("app_process32") else elf64())
        for name in ("system/etc/init", "vendor/etc/init"):
            (self.root / name).mkdir(parents=True)

    def put(self, name, data):
        p = self.root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
        p.chmod(0o755)
        return p

    def test_structure_pass_does_not_claim_boot(self):
        result = audit.audit(self.root, self.config)
        self.assertEqual(result["status"], "STATIC_USERSPACE_PREFLIGHT_PASS")
        self.assertFalse(result["android_boot_tested"])
        self.assertFalse(result["safe_to_flash"])

    def test_guest_absolute_symlink(self):
        (self.root / "init").unlink()
        self.put("system/bin/init", elf64())
        (self.root / "init").symlink_to("/system/bin/init")
        self.assertEqual(audit.guest_path(self.root, "/init"), self.root / "system/bin/init")
        self.assertFalse(audit.audit(self.root, self.config)["errors"])

    def test_guest_escape_and_loop(self):
        (self.root / "escape").symlink_to("../outside")
        (self.root / "loop").symlink_to("loop")
        for path in ("/escape", "/loop"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                audit.guest_path(self.root, path)

    def test_missing_binder(self):
        self.config.write_text(self.config.read_text().replace("CONFIG_ANDROID_BINDER_IPC=y",
                                                                "# CONFIG_ANDROID_BINDER_IPC is not set"))
        self.assertEqual(audit.audit(self.root, self.config)["status"], "REJECT_USERSPACE_PREFLIGHT")

    def test_wrong_arch(self):
        self.put("init", elf64(machine=62))
        self.assertTrue(audit.audit(self.root, self.config)["errors"])

    def test_missing_guest_linker(self):
        self.put("init", elf64(interp="/system/bin/linker64"))
        self.assertTrue(audit.audit(self.root, self.config)["errors"])
        self.put("system/bin/linker64", elf64())
        self.assertFalse(audit.audit(self.root, self.config)["errors"])

    def test_duplicate_config(self):
        with self.config.open("a") as f:
            f.write("CONFIG_ARM64=n\n")
        with self.assertRaises(ValueError):
            audit.config_check(self.config)

    def test_nonexecutable_init(self):
        (self.root / "init").chmod(0o644)
        self.assertTrue(audit.audit(self.root, self.config)["errors"])



class RegularReadTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.path = Path(tmp.name) / "donor"
        self.path.write_bytes(b"abcd")

    def test_regular_at_limit(self):
        self.assertEqual(audit.read_regular(self.path, 4), b"abcd")

    def test_oversized_and_empty(self):
        with self.assertRaises(ValueError):
            audit.read_regular(self.path, 3)
        self.path.write_bytes(b"")
        with self.assertRaises(ValueError):
            audit.read_regular(self.path, 4)

    def test_symlink_and_fifo(self):
        target = self.path.with_name("target")
        self.path.rename(target)
        self.path.symlink_to(target)
        with self.assertRaises(ValueError):
            audit.read_regular(self.path, 4)
        self.path.unlink()
        os.mkfifo(self.path)
        with self.assertRaises(ValueError):
            audit.read_regular(self.path, 4)

    def test_same_size_replacement_before_open(self):
        real_open = os.open

        def swap(path, flags):
            replacement = self.path.with_name("replacement")
            replacement.write_bytes(b"evil")
            replacement.replace(self.path)
            return real_open(path, flags)

        with mock.patch.object(audit.os, "open", side_effect=swap):
            with self.assertRaisesRegex(ValueError, "before reading"):
                audit.read_regular(self.path, 4)

    def test_symlink_replacement_before_open(self):
        real_open = os.open
        target = self.path.with_name("target")
        target.write_bytes(b"evil")

        def swap(path, flags):
            self.path.unlink()
            self.path.symlink_to(target)
            return real_open(path, flags)

        with mock.patch.object(audit.os, "open", side_effect=swap):
            with self.assertRaises(OSError):
                audit.read_regular(self.path, 4)

    def test_same_size_mutation_during_read(self):
        real_read = os.read

        def mutate(fd, size):
            data = real_read(fd, size)
            if data:
                self.path.write_bytes(b"evil")
                # Force distinct metadata even on coarse timestamp filesystems.
                old = self.path.stat()
                os.utime(self.path, ns=(old.st_atime_ns, old.st_mtime_ns - 10**9))
            return data

        with mock.patch.object(audit.os, "read", side_effect=mutate):
            with self.assertRaisesRegex(ValueError, "while reading"):
                audit.read_regular(self.path, 4)

    def test_path_replacement_during_read(self):
        real_read = os.read

        def swap(fd, size):
            data = real_read(fd, size)
            if data:
                replacement = self.path.with_name("replacement")
                replacement.write_bytes(b"evil")
                replacement.replace(self.path)
            return data

        with mock.patch.object(audit.os, "read", side_effect=swap):
            with self.assertRaisesRegex(ValueError, "while reading"):
                audit.read_regular(self.path, 4)


if __name__ == "__main__":
    unittest.main()
