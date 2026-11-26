"""Actual ARM32 ELF compilation -> audit -> atomic tzlite staging, never execute ELF."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"build"))
import r800_tzlite_audit as audit
import r800_stage_tzlite as stage
import r800_tzlite_manifest as manifest
from r800_tzlite_image_binding import compare
from r800_tzlite_legacy_image_scope import inspect_image
from r800_stage_tzlite_extended import stage as stage_extended
import r800_gnss_readiness as readiness

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
        loader=result["dac_candidates"]["aliases"]["/lib/ld-linux.so.3"]
        self.assertIn("execute",loader)
        self.assertEqual(loader["read"]["canonical"],LOADER)
        self.assertFalse(loader["read"]["canonical_path_only"])
        metadata=result["original_metadata"]
        self.assertEqual(metadata["status"],"ORIGINAL_METADATA_INVENTORY_ONLY")
        self.assertEqual(metadata["entries"]["/usr/bin/lhd"]["mode"],"0o755")
        self.assertEqual(metadata["entries"]["/lib"]["kind"],"symlink")
        self.assertEqual(metadata["entries"]["/usr/bin"]["kind"],"directory")
        self.assertFalse(metadata["ownership_restored"])
        self.assertGreaterEqual(result["elf_count"],24)
        self.assertEqual(result["image_sha256"],sha)
        self.assertEqual(result["manifest_sha256"],digest)
        self.assertFalse(result["donor_authenticity_verified"])
        self.assertFalse(result["safe_to_flash"])
        self.assertEqual(hashlib.sha256(image.read_bytes()).hexdigest(),sha)

    def test_actual_image_readiness_gate(self):
        digest=self.candidate_digest()
        image,sha=self.image_fixture()
        gates=[
            readiness.tzlite_integrity_gate(self.output,digest),
            readiness.static_gate("tzlite_known_components","r800_tzlite_audit.py",
                                  ["--root",self.output],"TZLITE_KNOWN_STATIC_CANDIDATES_ONLY"),
            readiness.static_gate("tizen_image_closure","r800_gps_image_audit.py",
                                  ["--image",image,"--sha256",sha],"STATIC_IMAGE_GNSS_CLOSURE_ONLY"),
        ]
        self.assertTrue(all(g["status"]=="STATIC_PASS" for g in gates),gates)
        result=readiness.tzlite_image_gate(self.output,image,sha,digest,gates)
        self.assertEqual(result["status"],"STATIC_PASS",result)
        self.assertEqual(result["detail"]["image_sha256"],sha)
        self.assertFalse(result["detail"]["runtime_verified"])
        self.assertFalse(result["detail"]["safe_to_flash"])

    def test_original_metadata_not_restored(self):
        path=self.root/"usr/bin/lhd"
        path.chmod(0o4755)
        digest=self.candidate_digest()
        image,_=self.image_fixture()
        # Write only this disposable test image to set distinctive numeric owners.
        subprocess.run(["debugfs","-w","-R","set_inode_field /usr/bin/lhd uid 12345",str(image)],
                       check=True,timeout=30,capture_output=True)
        subprocess.run(["debugfs","-w","-R","set_inode_field /usr/bin/lhd gid 23456",str(image)],
                       check=True,timeout=30,capture_output=True)
        sha=hashlib.sha256(image.read_bytes()).hexdigest()
        result=compare(self.output,image,sha,digest)
        self.assertEqual(result["status"],"STATIC_IMAGE_COMPONENT_MATCH_ONLY",result)
        meta=result["original_metadata"]
        record=meta["entries"]["/usr/bin/lhd"]
        self.assertEqual((record["uid"],record["gid"],record["mode"]),(12345,23456,"0o4755"))
        self.assertIn("SPECIAL_PRIVILEGE_MODE:/usr/bin/lhd",meta["review_candidates"])
        self.assertEqual((self.output/"usr/bin/lhd").stat().st_mode&0o7777,0o755)
        self.assertFalse(result["original_ownership_verified"])
        self.assertFalse(meta["effective_access_verified"])
        comparison=result["permission_comparison"]
        differences=comparison["metadata_differences"]["/usr/bin/lhd"]["fields"]
        self.assertEqual(differences["mode"],{"original":"0o4755","staged":"0o755"})
        self.assertEqual(differences["uid"]["original"],12345)
        self.assertFalse(comparison["permission_changes_applied"])
        plan=result["metadata_review_plan"]
        self.assertEqual(plan["image_sha256"],sha)
        self.assertEqual(plan["manifest_sha256"],digest)
        self.assertTrue(any(i["path"]=="/usr/bin/lhd" and i["category"]=="PRIVILEGE_REVIEW"
                            for i in plan["items"]))
        self.assertFalse(plan["execution_authorized"])
        self.assertEqual(hashlib.sha256(image.read_bytes()).hexdigest(),sha)

    def test_original_xattr_inventory_not_restored(self):
        digest=self.candidate_digest()
        image,_=self.image_fixture()
        # Only edit the disposable synthetic image, never the host file.
        for request in ("ea_set /usr/bin/lhd user.fixture private-fixture-value",
                        "ea_set /usr/bin/lhd security.selinux fixture-label"):
            subprocess.run(["debugfs","-w","-R",request,str(image)],
                           check=True,timeout=30,capture_output=True)
        sha=hashlib.sha256(image.read_bytes()).hexdigest()
        result=compare(self.output,image,sha,digest)
        self.assertEqual(result["status"],"STATIC_IMAGE_COMPONENT_MATCH_ONLY",result)
        meta=result["original_metadata"]
        attrs=meta["entries"]["/usr/bin/lhd"]["xattr_inventory"]
        self.assertEqual(attrs["status"],"ATTRIBUTES_REPORTED")
        self.assertEqual(attrs["attributes"]["user.fixture"]["reported_bytes"],21)
        self.assertEqual(attrs["attributes"]["security.selinux"]["category"],"selinux_label")
        self.assertIn("SECURITY_XATTR_REVIEW:/usr/bin/lhd:security.selinux",meta["review_candidates"])
        self.assertNotIn("private-fixture-value",str(result))
        self.assertNotIn("fixture-label",str(result))
        self.assertNotIn("user.fixture",os.listxattr(self.output/"usr/bin/lhd"))
        self.assertFalse(meta["xattrs_verified"])
        self.assertFalse(meta["capabilities_verified"])
        self.assertEqual(hashlib.sha256(image.read_bytes()).hexdigest(),sha)

    def test_binary_security_attributes_not_restored(self):
        digest=self.candidate_digest()
        image,_=self.image_fixture()
        # Synthetic values are written only to this disposable ext4 image.
        undefined=0xffffffff
        entries=[(1,7,undefined),(2,4,5001),(4,4,undefined),
                 (16,5,undefined),(32,5,undefined)]
        acl=struct.pack("<I",2)+b"".join(struct.pack("<HHI",*entry) for entry in entries)
        cap=struct.pack("<IIIII",0x02000001,1,0,0,0)
        for name,value in (("system.posix_acl_access",acl),("security.capability",cap)):
            (self.parent/"value").write_bytes(value)
            subprocess.run(["debugfs","-w","-R","ea_set -f value /usr/bin/lhd "+name,str(image)],
                           cwd=self.parent,check=True,timeout=30,capture_output=True)
        sha=hashlib.sha256(image.read_bytes()).hexdigest()
        result=compare(self.output,image,sha,digest)
        self.assertEqual(result["status"],"STATIC_IMAGE_COMPONENT_MATCH_ONLY",result)
        meta=result["original_metadata"]
        attrs=meta["entries"]["/usr/bin/lhd"]["xattr_inventory"]["attributes"]
        acl_record=attrs["system.posix_acl_access"]
        self.assertTrue(acl_record["structure"]["mode_consistent"])
        self.assertEqual(acl_record["structure"]["format"],"EXT4_DISK_ACL_V1")
        self.assertEqual(acl_record["reported_bytes"],28)
        self.assertEqual(acl_record["structure"]["disk_bytes"],28)
        self.assertEqual(acl_record["structure"]["entry_count"],5)
        dac=result["dac_candidates"]
        self.assertEqual(dac["uid_candidate"],5001)
        self.assertEqual(dac["primary_gid_candidate"],5002)
        self.assertEqual(acl_record["structure"]["dac_candidate"]["selected_class"],"named_user")
        self.assertEqual(dac["files"]["/usr/bin/lhd"]["execute"]["status"],"DENIED_CANDIDATE")
        self.assertEqual(dac["files"]["/usr/bin/lhd"]["execute"]["denied_paths"],["/usr/bin/lhd"])
        self.assertFalse(dac["process_identity_verified"])
        self.assertFalse(dac["effective_access_verified"])
        self.assertEqual(attrs["security.capability"]["structure"]["permitted_count"],1)
        self.assertNotIn("security.capability",os.listxattr(self.output/"usr/bin/lhd"))
        self.assertFalse(meta["acl_verified"])
        self.assertFalse(meta["capabilities_verified"])
        self.assertEqual(hashlib.sha256(image.read_bytes()).hexdigest(),sha)

    def test_image_alias_detour_dac(self):
        private=self.root/"usr/lib/private"
        private.mkdir(mode=0o700)
        alias=self.root/ALIAS.lstrip("/")
        alias.unlink()
        alias.symlink_to("private/../libfixture-real.so")
        digest=self.candidate_digest()
        image,sha=self.image_fixture()
        result=compare(self.output,image,sha,digest)
        self.assertEqual(result["status"],"STATIC_IMAGE_COMPONENT_MATCH_ONLY",result)
        dac=result["dac_candidates"]
        alias_read=dac["aliases"]["/lib/libfixture.so.1"]["read"]
        self.assertEqual(alias_read["status"],"DENIED_CANDIDATE")
        self.assertIn("/usr/lib/private",alias_read["denied_paths"])
        self.assertEqual(dac["files"][PROVIDER]["read"]["status"],"CONDITIONAL_MODE_CANDIDATE")
        self.assertEqual(result["original_metadata"]["entries"]["/usr/lib/private"]["kind"],"directory")
        self.assertFalse(dac["alias_traversal_verified"])
        self.assertFalse(dac["effective_access_verified"])

    def test_extra_plugin_real_elf(self):
        plugin=self.root/"usr/lib/sensor/extra.so"
        shutil.copyfile(self.root/audit.PLUGINS[0].lstrip("/"),plugin)
        image,sha=self.image_fixture()
        result=inspect_image(image,sha,extended_manifest=True)
        report=result["extra_plugin_audit"]
        self.assertEqual(report["status"],"STATIC_EXTRA_PLUGIN_CLOSURE_ONLY",report["problems"])
        self.assertEqual(report["candidate_count"],1)
        path="/usr/lib/sensor/extra.so"
        self.assertEqual(report["candidates"][path]["sha256"],hashlib.sha256(plugin.read_bytes()).hexdigest())
        self.assertIn("libfixture.so.1",report["dependency_evidence"]["files"][path]["needed"])
        self.assertFalse(report["dlopen_verified"])
        extended=result["extended_manifest"]
        self.assertEqual(extended["files"][path]["category"],"AUDITED_ELF")
        self.assertEqual(extended["files"]["/etc/passwd"]["category"],"KNOWN_CONFIG")
        self.assertEqual(extended["image_sha256"],sha)
        self.assertFalse(extended["staging_authorized"])
        self.assertEqual(hashlib.sha256(image.read_bytes()).hexdigest(),sha)

    def test_extra_plugin_bad_elf(self):
        (self.root/"usr/lib/sensor/broken.so").write_bytes(b"\x7fELFbroken")
        image,sha=self.image_fixture()
        report=inspect_image(image,sha,audit_plugins=True)
        self.assertIn("EXTRA_PLUGIN_CLOSURE_REVIEW",report["problems"])
        extra=report["extra_plugin_audit"]
        self.assertEqual(extra["status"],"REVIEW_REQUIRED")
        self.assertEqual(extra["candidates"]["/usr/lib/sensor/broken.so"]["status"],"REVIEW_REQUIRED")
        self.assertFalse(extra["safe_to_flash"])

    def test_extra_plugin_no_candidates(self):
        image,sha=self.image_fixture()
        extra=inspect_image(image,sha,audit_plugins=True)["extra_plugin_audit"]
        self.assertEqual(extra["status"],"NO_ADDITIONAL_ELF_CANDIDATES_REPORTED")
        self.assertFalse(extra["plugin_completeness_verified"])

    def test_extended_stage_subset(self):
        plugin=self.root/"usr/lib/sensor/extra.so"
        shutil.copyfile(self.root/audit.PLUGINS[0].lstrip("/"),plugin)
        (self.root/"etc/info.ini").write_bytes(b"unreviewed")
        image,sha=self.image_fixture()
        review=inspect_image(image,sha,extended_manifest=True)
        report=stage_extended(image,self.output,sha,review["extended_manifest_sha256"])
        self.assertEqual(report["status"],"EXTENDED_STATIC_CANDIDATE_ONLY")
        self.assertEqual((self.output/"usr/lib/sensor/extra.so").read_bytes(),plugin.read_bytes())
        self.assertIn("/etc/info.ini",report["excluded_unreviewed_data"])
        self.assertFalse((self.output/"etc/info.ini").exists())
        self.assertFalse(report["safe_to_flash"])
        self.assertEqual(hashlib.sha256(image.read_bytes()).hexdigest(),sha)
        self.assertEqual(hashlib.sha256((self.output/manifest.MANIFEST).read_bytes()).hexdigest(),
                         report["stage_manifest_sha256"])
        with self.assertRaises(ValueError):
            manifest.verify(self.output,report["stage_manifest_sha256"])

    def test_extended_stage_wrong_review(self):
        image,sha=self.image_fixture()
        with self.assertRaisesRegex(ValueError,"review manifest SHA-256"):
            stage_extended(image,self.output,sha,"0"*64)
        self.assertFalse(self.output.exists())

    def test_extended_stage_existing_output(self):
        image,sha=self.image_fixture()
        self.output.mkdir()
        marker=self.output/"marker"
        marker.write_bytes(b"keep")
        with self.assertRaisesRegex(ValueError,"Output must be new"):
            stage_extended(image,self.output,sha,"0"*64)
        self.assertEqual(marker.read_bytes(),b"keep")

    def test_image_configuration_changed(self):
        digest=self.candidate_digest()
        (self.root/"etc/lhd/lhd.conf").write_bytes(b"different synthetic config\n")
        image,sha=self.image_fixture()
        result=compare(self.output,image,sha,digest)
        self.assertIn("IMAGE_CONFIGURATION_HASH_MISMATCH",result["problems"])
        self.assertEqual(result["metadata_review_plan"]["status"],"BLOCKED_CONTENT_MISMATCH")
        self.assertEqual(result["metadata_review_plan"]["items"],[])

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
