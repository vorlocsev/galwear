"""Actual ARM32 ELF compilation -> audit -> atomic tzlite staging, never execute ELF."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"build"))
import r800_tzlite_audit as audit
import r800_stage_tzlite as stage
import r800_tzlite_manifest as manifest
from r800_tzlite_image_binding import compare

PROVIDER="/usr/lib/libfixture-real.so"
ALIAS="/usr/lib/libfixture.so.1"
LOADER="/usr/lib/ld-linux.so.3"
FLAGS=["clang","--target=armv7a-linux-gnueabi","-marm","-mfloat-abi=softfp",
       "-mfpu=vfpv3-d16","-fuse-ld=lld","-nostdlib","-ffreestanding",
       "-fno-stack-protector","-fno-unwind-tables","-fno-asynchronous-unwind-tables",
       "-O2","-Wl,--hash-style=sysv,-z,now,-z,noexecstack,--no-undefined"]


class RealStageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.geteuid()==0:
            raise RuntimeError("Real static staging fixture requires an unprivileged runner")
        temp=tempfile.TemporaryDirectory(prefix="r800-tzlite-elf-")
        cls.addClassCleanup(temp.cleanup)
        cls.work=Path(temp.name)
        cls.template=cls.work/"template"
        cls.template.mkdir()
        for guest in audit.MOUNTPOINTS+audit.REQUIRED_TREES+("/usr/bin","/usr/lib"):
            (cls.template/guest.lstrip("/")).mkdir(parents=True,exist_ok=True)
        (cls.template/"lib").symlink_to("usr/lib",target_is_directory=True)

        def compile_file(name,source,options):
            src=cls.work/"fixture.c"
            src.write_text(source)
            dest=cls.template/name.lstrip("/")
            subprocess.run(FLAGS+[str(src),*options,"-o",str(dest)],check=True,timeout=30,
                           capture_output=True)
            return dest

        compile_file(PROVIDER,"int fixture_value(void) { return 17; }\n",
                     ["-fPIC","-shared","-Wl,-soname,libfixture.so.1"])
        (cls.template/ALIAS.lstrip("/")).symlink_to("libfixture-real.so")
        # Only a synthetic ELF with the loader's expected path; never run it.
        compile_file(LOADER,"int fixture_loader(void) { return 0; }\n",
                     ["-fPIC","-shared","-Wl,-soname,ld-linux.so.3"])
        provider=str(cls.template/ALIAS.lstrip("/"))
        for guest in audit.PLUGINS:
            compile_file(guest,"extern int fixture_value(void);\n"
                         "int gps_get_hardware_interface(void) { return fixture_value(); }\n",
                         ["-fPIC","-shared","-Wl,-soname,"+Path(guest).name,provider])
        executable=compile_file(audit.PROGRAMS[0],
                               "extern int fixture_value(void);\n"
                               "int _start(void) { return fixture_value(); }\n",
                               ["-fPIE","-pie","-Wl,-e,_start,--dynamic-linker=/lib/ld-linux.so.3",
                                provider])
        for guest in audit.PROGRAMS[1:]:
            shutil.copyfile(executable,cls.template/guest.lstrip("/"))
            (cls.template/guest.lstrip("/")).chmod(0o755)
        for guest,data in (("/etc/lhd/lhd.conf",b"synthetic config\n"),
                           ("/etc/gps-manager/brcm/gpsd.xml",b"<gpsd/>"),
                           ("/etc/passwd",b"location:x:5001:5002::/:/bin/false\n"),
                           ("/etc/group",b"location:x:5002:\n")):
            dest=cls.template/guest.lstrip("/")
            dest.parent.mkdir(parents=True,exist_ok=True)
            dest.write_bytes(data)

    def setUp(self):
        temp=tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.parent=Path(temp.name)
        self.root=self.parent/"source"
        shutil.copytree(self.template,self.root,symlinks=True)
        self.output=self.parent/"candidate"

    def test_actual_elf_audit(self):
        report=audit.check(self.root)
        self.assertEqual(report["status"],"TZLITE_KNOWN_STATIC_CANDIDATES_ONLY",report)
        closure=report["dependency_evidence"]
        self.assertEqual(set(closure["symbol_candidates"]["targets"]),set(audit.TARGETS))
        self.assertEqual(closure["aliases"]["/lib/libfixture.so.1"],PROVIDER)
        self.assertEqual(closure["aliases"]["/lib/ld-linux.so.3"],LOADER)
        for name in audit.PROGRAMS:
            item=closure["files"][name]
            self.assertEqual(item["interpreter"],"/lib/ld-linux.so.3")
            self.assertIn("libfixture.so.1",item["needed"])
            self.assertGreater(closure["symbol_candidates"]["targets"][name]["matched"],0)
        self.assertFalse(report["safe_to_flash"])

    def test_actual_staging_roundtrip(self):
        report=stage.stage(self.root,self.output)
        self.assertEqual(report["status"],"TZLITE_STATIC_CANDIDATE_ONLY")
        self.assertFalse(report["runtime_verified"])
        self.assertFalse(report["safe_to_flash"])
        self.assertEqual(report,json.loads((self.output/"tzlite-static-evidence.json").read_text()))
        for name,record in report["files"].items():
            self.assertEqual(hashlib.sha256((self.output/name.lstrip("/")).read_bytes()).hexdigest(),
                             record["sha256"])
        self.assertTrue((self.output/"lib/libfixture.so.1").is_symlink())
        self.assertEqual((self.output/"lib/libfixture.so.1").resolve(),
                         self.output/PROVIDER.lstrip("/"))
        self.assertEqual(audit.check(self.output)["status"],"TZLITE_KNOWN_STATIC_CANDIDATES_ONLY")
        digest=hashlib.sha256((self.output/manifest.MANIFEST).read_bytes()).hexdigest()
        self.assertEqual(manifest.verify(self.output,digest)["status"],"STATIC_TREE_INTEGRITY_ONLY")

    def image_fixture(self):
        image=self.parent/"rootfs.img"
        with image.open("wb") as f:
            f.truncate(16*1024**2)
        subprocess.run(["mkfs.ext4","-q","-F","-d",str(self.root),str(image)],
                       check=True,timeout=30)
        return image,hashlib.sha256(image.read_bytes()).hexdigest()

    def candidate_digest(self):
        stage.stage(self.root,self.output)
        return hashlib.sha256((self.output/manifest.MANIFEST).read_bytes()).hexdigest()

    def test_image_component_binding(self):
        digest=self.candidate_digest()
        image,sha=self.image_fixture()
        result=compare(self.output,image,sha,digest)
        self.assertEqual(result["status"],"STATIC_IMAGE_COMPONENT_MATCH_ONLY",result)
        self.assertEqual(result["configuration_count"],4)
        self.assertGreaterEqual(result["elf_count"],24)
        self.assertEqual(result["image_sha256"],sha)
        self.assertEqual(result["manifest_sha256"],digest)
        self.assertFalse(result["donor_authenticity_verified"])
        self.assertFalse(result["safe_to_flash"])
        self.assertEqual(hashlib.sha256(image.read_bytes()).hexdigest(),sha)

    def test_image_configuration_changed(self):
        digest=self.candidate_digest()
        (self.root/"etc/lhd/lhd.conf").write_bytes(b"different synthetic config\n")
        image,sha=self.image_fixture()
        self.assertIn("IMAGE_CONFIGURATION_HASH_MISMATCH",
                      compare(self.output,image,sha,digest)["problems"])

    def test_image_elf_changed(self):
        digest=self.candidate_digest()
        path=self.root/PROVIDER.lstrip("/")
        with path.open("ab") as f:
            f.write(b"synthetic trailing bytes")
        image,sha=self.image_fixture()
        self.assertIn("IMAGE_ELF_CLOSURE_MISMATCH",
                      compare(self.output,image,sha,digest)["problems"])

    def test_image_digest_mismatch(self):
        digest=self.candidate_digest()
        image,_=self.image_fixture()
        with self.assertRaisesRegex(ValueError,"SHA-256"):
            compare(self.output,image,"0"*64,digest)

    def test_candidate_mutated(self):
        digest=self.candidate_digest()
        image,sha=self.image_fixture()
        (self.output/"extra").write_bytes(b"unexpected")
        with self.assertRaises(ValueError):
            compare(self.output,image,sha,digest)

    def test_missing_real_dependency(self):
        (self.root/PROVIDER.lstrip("/")).unlink()
        result=audit.check(self.root)
        self.assertIn("TZLITE_DEPENDENCY_REVIEW",result["problems"])
        with self.assertRaises(ValueError):
            stage.stage(self.root,self.output)
        self.assertFalse(self.output.exists())

    def test_wrong_real_elf_abi(self):
        path=self.root/audit.PROGRAMS[0].lstrip("/")
        raw=bytearray(path.read_bytes())
        raw[18:20]=(62).to_bytes(2,"little")  # incompatible ELF machine
        path.write_bytes(raw)
        self.assertIn("TZLITE_DEPENDENCY_REVIEW",audit.check(self.root)["problems"])
        with self.assertRaises(ValueError):
            stage.stage(self.root,self.output)
        self.assertFalse(self.output.exists())

    def test_missing_real_plugin(self):
        (self.root/audit.PLUGINS[-1].lstrip("/")).unlink()
        self.assertIn("TZLITE_TARGET_MISSING:"+audit.PLUGINS[-1],audit.check(self.root)["problems"])
        with self.assertRaises(ValueError):
            stage.stage(self.root,self.output)
        self.assertFalse(self.output.exists())


if __name__=="__main__":
    unittest.main()
