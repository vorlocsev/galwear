"""Selected NDK pins: synthetic tools, no compiler execution."""
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"build"))
import r800_ndk_pins as ndk


class NdkPinsTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root=Path(tmp.name)
        self.bin=self.root/ndk.BIN
        self.bin.mkdir(parents=True)
        self.prop=self.root/"source.properties"
        self.prop.write_text("Pkg.Desc = Android NDK\nPkg.Revision = "+ndk.REVISION+"\n")
        for name in ndk.TOOLS:
            p=self.bin/name
            p.write_bytes(name.encode())
            p.chmod(0o755)
        self.pins={k:v["sha256"] for k,v in ndk.observe(self.root).items()}

    def test_exact_pins(self):
        report=ndk.verify(self.root,self.pins)
        self.assertEqual(report["status"],"SELECTED_NDK_TOOL_PINS_MATCH_ONLY")
        self.assertFalse(report["complete_ndk_verified"])
        self.assertFalse(report["host_libraries_verified"])
        self.assertFalse(report["safe_to_flash"])

    def test_changed_tool(self):
        (self.bin/"clang").write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError,"selected file pin mismatch"):
            ndk.verify(self.root,self.pins)

    def test_wrong_revision(self):
        self.prop.write_text("Pkg.Revision = 28.0.0\n")
        with self.assertRaisesRegex(ValueError,"unique NDK r27c revision"):
            ndk.verify(self.root,self.pins)

    def test_duplicate_revision(self):
        with self.prop.open("a") as out:
            out.write("Pkg.Revision = "+ndk.REVISION+"\n")
        with self.assertRaisesRegex(ValueError,"unique NDK r27c revision"):
            ndk.observe(self.root)

    def test_incomplete_pins(self):
        del self.pins["ld.lld"]
        with self.assertRaisesRegex(ValueError,"Four explicit"):
            ndk.verify(self.root,self.pins)

    def test_internal_symlink(self):
        clang=self.bin/"clang"
        target=self.bin/"clang-18"
        clang.rename(target)
        clang.symlink_to(target.name)
        self.assertEqual(ndk.verify(self.root,self.pins)["files"]["clang"]["resolved"],
                         (ndk.BIN/"clang-18").as_posix())

    def test_external_symlink(self):
        clang=self.bin/"clang"
        target=self.root/"external"
        clang.rename(target)
        clang.symlink_to(target)
        with self.assertRaisesRegex(ValueError,"within bin"):
            ndk.observe(self.root)

    def test_nonexecutable(self):
        (self.bin/"llvm-readelf").chmod(0o644)
        with self.assertRaisesRegex(ValueError,"executable"):
            ndk.observe(self.root)


if __name__=="__main__":
    unittest.main()
