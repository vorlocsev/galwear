"""Exercise only the base vendor tar recipe with synthetic files, never mount."""
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

SCRIPT=Path(__file__).resolve().parents[1]/"build/build_vendor.sh"
MEMBERS=set("""
./etc/selinux ./etc/vintf ./etc/fs_config_dirs ./etc/fs_config_files ./etc/group ./etc/passwd
./etc/seccomp_policy ./etc/permissions ./etc/media_codecs.xml ./etc/media_codecs_google_audio.xml
./etc/media_codecs_google_telephony.xml ./etc/media_profiles_vendor.xml
./etc/init/vndservicemanager.rc ./bin/vndservicemanager ./lib/hw/gralloc.default.so
./default.prop ./build.prop ./lib/hw/android.hardware.graphics.mapper@2.0-impl.so
./lib/hw/android.hardware.graphics.allocator@2.0-impl.so
./bin/hw/android.hardware.configstore@1.1-service ./etc/init/android.hardware.configstore@1.1-service.rc ./lib/libhwminijail.so
./bin/hw/android.hardware.power@1.0-service ./etc/init/android.hardware.power@1.0-service.rc
./lib/hw/android.hardware.power@1.0-impl.so ./lib/hw/power.default.so
./bin/hw/android.hardware.health@2.0-service ./etc/init/android.hardware.health@2.0-service.rc
./bin/hw/android.hardware.graphics.allocator@2.0-service ./etc/init/android.hardware.graphics.allocator@2.0-service.rc
""".split())


class VendorBaseTarTests(unittest.TestCase):
    def test_shell_syntax(self):
        subprocess.run(["bash","-n",str(SCRIPT)],check=True,timeout=10)

    def test_base_tar_members(self):
        text=SCRIPT.read_text()
        marker="# keep: policy, vintf, permissions, props, uid tables, codecs; vndservicemanager; generic gralloc"
        start=text.index(marker)+len(marker)
        end=text.index("# vndservicemanager deps",start)
        recipe=text[start:end].strip()
        members=re.findall(r"\./[A-Za-z0-9_.@/-]+",recipe)
        self.assertEqual(set(members),MEMBERS)
        self.assertEqual(len(members),len(MEMBERS))
        self.assertNotIn(r"\n",recipe)
        # Only run the narrowly recognized tar pipeline, not the enclosing script.
        normalized=recipe.replace("\\\n"," ")
        expected="tar --xattrs --xattrs-include='*' -cf - "
        self.assertTrue(normalized.startswith(expected))
        self.assertRegex(normalized[len(expected):],
                         r"""^\s*(?:\./[A-Za-z0-9_.@/-]+\s+)+\|\s*tar --xattrs --xattrs-include='\*' -C "\$OUT" -xpf -$""")
        with tempfile.TemporaryDirectory() as tmp:
            source=Path(tmp)/"source"
            out=Path(tmp)/"out space"
            source.mkdir()
            out.mkdir()
            for name in MEMBERS:
                p=source/name
                p.parent.mkdir(parents=True,exist_ok=True)
                p.write_text(name)
            subprocess.run(["bash","-e","-o","pipefail","-c",recipe],
                           cwd=source,env={**os.environ,"OUT":str(out)},
                           check=True,timeout=15)
            self.assertEqual({p.relative_to(out).as_posix() for p in out.rglob("*") if p.is_file()},
                             {n[2:] for n in MEMBERS})
            for name in MEMBERS:
                self.assertEqual((out/name).read_text(),name)


if __name__=="__main__":
    unittest.main()
