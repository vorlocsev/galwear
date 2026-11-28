"""Development Kconfig contract tests; do not compile or boot a kernel."""
from pathlib import Path
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"build"))
import r800_development_kernel as kernel
from r800_development_initramfs import SOURCE_CONFIG


class DevelopmentKernelTests(unittest.TestCase):
    path="/scratch/initramfs/initramfs.cpio"

    def config(self):
        return (ROOT/"src/kernel/r800.config").read_text().replace(
            SOURCE_CONFIG,'CONFIG_INITRAMFS_SOURCE="'+self.path+'"')

    def test_effective_config(self):
        values=kernel.check_effective(self.config().encode(),self.path)
        for key in ("CONFIG_MMC","CONFIG_MMC_BLOCK","CONFIG_BLK_DEV_LOOP",
                    "CONFIG_ANDROID_BINDER_IPC","CONFIG_EXT4_FS","CONFIG_COMPAT"):
            self.assertEqual(values[key],"y")

    def test_disabled_storage(self):
        for key in ("CONFIG_MMC","CONFIG_MMC_BLOCK","CONFIG_BLK_DEV_LOOP"):
            with self.subTest(key=key):
                raw=self.config().replace(key+"=y","# "+key+" is not set").encode()
                with self.assertRaisesRegex(ValueError,"Effective kernel prerequisites missing"):
                    kernel.check_effective(raw,self.path)

    def test_wrong_archive(self):
        with self.assertRaisesRegex(ValueError,"Effective initramfs source differs"):
            kernel.check_effective(self.config().encode(),"/scratch/other.cpio")

    def test_binder_mismatch(self):
        raw=self.config().replace('"binder,hwbinder,vndbinder"','"binder"').encode()
        with self.assertRaisesRegex(ValueError,"CONFIG_ANDROID_BINDER_DEVICES"):
            kernel.check_effective(raw,self.path)

    def test_unsafe_archive_path(self):
        with tempfile.TemporaryDirectory(prefix="unsafe path ") as tmp:
            root=Path(tmp)
            (root/"initramfs.cpio").write_bytes(b"x")
            with self.assertRaisesRegex(ValueError,"Unsafe development CPIO path"):
                kernel.archive_path(root)


if __name__=="__main__":
    unittest.main()
