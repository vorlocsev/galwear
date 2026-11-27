"""Real ext4 fixture generated from synthetic data; no mount or real donor."""
import hashlib
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/"build"))
from r800_extract_ext4 import extract, HCD
import r800_extract_ext4 as extractor


@unittest.skipUnless(shutil.which("debugfs") and shutil.which("mkfs.ext4"), "e2fsprogs unavailable")
class Ext4ExtractionTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.tree = self.root/"fixture"
        self.tree.mkdir()
        self.image = self.root/"rootfs.img"
        self.output = self.root/"out"

    def put(self, name, data):
        p = self.tree/name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
        return p

    def make_image(self):
        with self.image.open("wb") as f:
            f.truncate(16*1024**2)
        subprocess.run(["mkfs.ext4", "-q", "-F", "-d", str(self.tree), str(self.image)],
                       check=True, timeout=30)
        return hashlib.sha256(self.image.read_bytes()).hexdigest()

    def test_read_only_tizen_allowlist(self):
        self.put("usr/lib/firmware/"+HCD, b"synthetic HCD")
        self.put("lib/libc-2.24.so", b"synthetic libc")
        self.put("home/user/private.txt", b"excluded")
        sha = self.make_image()
        report = extract(self.image, self.output, "tizen", sha)
        self.assertEqual((self.output/"tizen/libc.so.6").read_bytes(), b"synthetic libc")
        self.assertEqual((self.output/"payload/fw/bt"/HCD).read_bytes(), b"synthetic HCD")
        self.assertFalse((self.output/"home").exists())
        self.assertIn("tizen/libdl.so.2", report["missing_or_ambiguous"])
        self.assertEqual(hashlib.sha256(self.image.read_bytes()).hexdigest(), sha)
        self.assertFalse(report["safe_to_flash"])

    def test_gps_profile_extracts_only_four_resolved_libraries(self):
        names = {"libc.so.6": "libc-2.24.so", "libdl.so.2": "libdl-2.24.so",
                 "libpthread.so.0": "libpthread-2.24.so", "ld-linux.so.3": "ld-2.24.so"}
        for dest, source in names.items():
            self.put("lib/"+source, dest.encode())
        self.put("usr/lib/firmware/"+HCD, b"excluded radio")
        self.put("home/user/private.txt", b"excluded private")
        sha = self.make_image()
        report = extract(self.image, self.output, "tizen-gps", sha)
        self.assertEqual(set(report["files"]), {"tizen/"+n for n in names})
        self.assertEqual(report["missing_or_ambiguous"], [])
        for name in names:
            self.assertEqual((self.output/"tizen"/name).read_bytes(), name.encode())
        self.assertFalse((self.output/"payload").exists())
        self.assertFalse((self.output/"home").exists())
        self.assertFalse(report["donor_compatibility_verified"])
        self.assertFalse(report["safe_to_flash"])

    def test_gps_profile_missing_loader_blocks(self):
        self.put("lib/libc-2.24.so", b"synthetic libc")
        sha = self.make_image()
        report = extract(self.image, self.output, "tizen-gps", sha)
        self.assertIn("tizen/ld-linux.so.3", report["missing_or_ambiguous"])
        self.assertEqual(report["files"]["tizen/ld-linux.so.3"]["status"], "MISSING")

    def test_gps_profile_ambiguous_loader_blocks(self):
        self.put("lib/ld-2.24.so", b"one")
        self.put("usr/lib/ld-2.24.so", b"two")
        sha = self.make_image()
        report = extract(self.image, self.output, "tizen-gps", sha)
        self.assertEqual(report["files"]["tizen/ld-linux.so.3"]["status"], "AMBIGUOUS")
        self.assertFalse((self.output/"tizen/ld-linux.so.3").exists())

    def test_vendor_profile(self):
        self.put("lib/libeffectsconfig.so", b"synthetic library")
        sha = self.make_image()
        report = extract(self.image, self.output, "vendor", sha)
        self.assertEqual(report["files"]["vendor/lib/libeffectsconfig.so"]["status"], "EXTRACTED")
        self.assertTrue(report["missing_or_ambiguous"])

    def test_vendor_identity_reports_properties_and_incomplete_groups(self):
        self.put("build.prop", b"ro.product.vendor.model=Fixture Watch\nro.vendor.build.id=FIXTURE\nro.serialno=excluded\n")
        self.put("etc/vintf/manifest.xml", b"<manifest/>")
        self.put("bin/vndservicemanager", b"not ELF")
        sha = self.make_image()
        report = extract(self.image, self.output, "vendor-identity", sha)
        identity = report["vendor_identity"]
        self.assertEqual(identity["properties"], {
            "ro.product.vendor.model": "Fixture Watch", "ro.vendor.build.id": "FIXTURE"})
        self.assertTrue(identity["vintf_manifest_present"])
        self.assertEqual(identity["elf"]["vendor/bin/vndservicemanager"]["status"], "REJECTED")
        self.assertFalse(identity["hidl_groups"]["wifi"]["inventory_complete"])
        self.assertFalse(identity["identity_verified"])
        self.assertFalse(identity["safe_to_flash"])

    def test_vendor_vintf_hidl_declarations(self):
        manifest = self.put("etc/vintf/manifest.xml", b"""<manifest type="device">
          <hal format="hidl"><name>android.hardware.wifi</name>
          <transport>hwbinder</transport><version>1.0</version>
          <interface><name>IWifi</name><instance>default</instance></interface></hal>
          <hal format="hidl"><name>android.hardware.wifi.supplicant</name>
          <transport>hwbinder</transport><fqname>@1.0::ISupplicant/default</fqname></hal>
          <hal format="hidl"><name>android.hardware.sensors</name>
          <transport>hwbinder</transport><fqname>@1.0::ISensors/default</fqname></hal>
          <hal format="hidl"><name>android.hardware.gnss</name>
          <transport>hwbinder</transport><fqname>@1.0::IGnss/default</fqname></hal>
        </manifest>""")
        report = extractor.vintf_inventory(manifest)
        self.assertEqual(report["status"], "DECLARATIONS_PRESENT")
        self.assertFalse(report["compatibility_verified"])
        for old, new, group in ((b"@1.0::IGnss/default", b"@2.0::IGnss/default", "gnss"),
                                (b"@1.0::ISensors/default", b"@1.0::ISensors/other", "sensors"),
                                (b"<version>1.0</version>", b"<version>1.1</version>", "wifi")):
            with self.subTest(group=group):
                raw = manifest.read_bytes()
                manifest.write_bytes(raw.replace(old, new))
                report = extractor.vintf_inventory(manifest)
                self.assertEqual(report["status"], "REVIEW_REQUIRED")
                self.assertTrue(report["missing_by_group"][group])
                manifest.write_bytes(raw)
        sha = self.make_image()
        report = extract(self.image, self.output, "vendor-identity", sha)
        self.assertEqual(report["vendor_identity"]["vintf"]["status"], "DECLARATIONS_PRESENT")
        self.assertFalse(report["vendor_identity"]["identity_verified"])

    def test_vendor_vintf_rejects_dtd_malformed_and_wrong_type(self):
        for raw in (b'<!DOCTYPE manifest [<!ENTITY x "x">]><manifest type="device"/>',
                    b'<manifest type="framework"/>', b'<manifest type="device">',
                    '<!DOCTYPE manifest><manifest type="device"/>'.encode("utf-16")):
            with self.subTest(raw=raw):
                manifest = self.put("etc/vintf/manifest.xml", raw)
                report = extractor.vintf_inventory(manifest)
                self.assertEqual(report["status"], "REVIEW_REQUIRED")
                self.assertFalse(report["compatibility_verified"])

    def test_identity_inventory_requires_model_device_build_and_fingerprint(self):
        props = {"ro.product.vendor.model": "Fixture Watch",
                 "ro.product.vendor.device": "fixture",
                 "ro.product.vendor.brand": "example",
                 "ro.vendor.build.id": "BUILD1",
                 "ro.vendor.build.fingerprint": "example/product/fixture:9/BUILD1/123:user/release-keys",
                 "ro.vendor.build.version.release": "9",
                 "ro.vendor.build.version.sdk": "28"}
        report = extractor.identity_inventory(props, [])
        self.assertEqual(report["status"], "IDENTITY_FIELDS_PRESENT")
        self.assertEqual(report["fingerprint_fields"]["device"], "fixture")
        self.assertFalse(report["identity_verified"])
        self.assertFalse(report["compatibility_verified"])
        for key in extractor.IDENTITY_REQUIRED:
            with self.subTest(key=key):
                incomplete = dict(props)
                del incomplete[key]
                report = extractor.identity_inventory(incomplete, [])
                self.assertEqual(report["status"], "REVIEW_REQUIRED")
                self.assertIn(key, report["missing"])
        for key, value in (("ro.product.vendor.device", "other"),
                           ("ro.vendor.build.id", "BUILD2"),
                           ("ro.vendor.build.version.release", "11"),
                           ("ro.product.vendor.brand", "other"),
                           ("ro.vendor.build.version.sdk", "unknown"),
                           ("ro.vendor.build.fingerprint", "malformed")):
            with self.subTest(key=key):
                invalid = dict(props)
                invalid[key] = value
                report = extractor.identity_inventory(invalid, [])
                self.assertEqual(report["status"], "REVIEW_REQUIRED")
                self.assertTrue(report["problems"])
        self.assertEqual(extractor.identity_inventory(props, ["ro.product.vendor.model"])["status"],
                         "REVIEW_REQUIRED")
        self.put("build.prop", "".join(k + "=" + v + "\n" for k, v in props.items()).encode())
        sha = self.make_image()
        report = extract(self.image, self.output, "vendor-identity", sha)
        self.assertEqual(report["vendor_identity"]["identity_inventory"]["status"],
                         "IDENTITY_FIELDS_PRESENT")
        self.assertFalse(report["vendor_identity"]["identity_verified"])
        self.assertIn("vendor/default.prop", report["missing_or_ambiguous"])
        self.assertFalse(report["safe_to_flash"])

    def test_hidl_direct_dependencies_distinguish_candidate_scope(self):
        def obj(needed=(), soname=None, status="ARM32_DYNAMIC", elf_type="ET_DYN",
                search=False):
            return {"status": status, "needed": list(needed), "soname": soname,
                    "elf_type": elf_type, "custom_search_path": search}
        service = "vendor/bin/hw/test-service"
        same = "vendor/lib/libsame.so"
        other = "vendor/lib/libother.so"
        bad = "vendor/lib/libbad.so"
        absent = "vendor/lib/libmissing.so"
        elf = {service: obj(("libsame.so", "libother.so", "libbad.so", "libmissing.so",
                             "libhwonly.so")),
               same: obj(soname="libsame.so"),
               other: obj(soname="libother.so"),
               bad: obj(soname="libwrong.so"),
               "vendor/lib/hw/libhwonly.so": obj(soname="libhwonly.so")}
        report = extractor.hidl_dependency_inventory(elf, [service, same, absent])
        statuses = {e["needed"]: e["status"] for e in report["edges"]}
        self.assertEqual(statuses, {"libsame.so": "SAME_GROUP_CANDIDATE",
                                   "libother.so": "OTHER_GROUP_CANDIDATE",
                                   "libbad.so": "CANDIDATE_REJECTED",
                                   "libmissing.so": "OUTSIDE_SELECTED_INVENTORY",
                                   "libhwonly.so": "OUTSIDE_SELECTED_INVENTORY"})
        self.assertEqual(report["external_names"], ["libhwonly.so", "libmissing.so"])
        self.assertEqual(report["elf_review"][0]["object"], absent)
        self.assertEqual(report["status"], "REVIEW_REQUIRED")
        self.assertFalse(report["dependency_closure_verified"])
        self.assertFalse(report["namespace_resolution_verified"])

    def test_hidl_direct_inventory_never_claims_closure(self):
        service = "vendor/bin/hw/test-service"
        lib = "vendor/lib/libfixture.so"
        elf = {service: {"status": "ARM32_DYNAMIC", "needed": ["libfixture.so"],
                         "custom_search_path": False},
               lib: {"status": "ARM32_DYNAMIC", "needed": [], "elf_type": "ET_DYN",
                     "soname": "libfixture.so", "custom_search_path": False}}
        report = extractor.hidl_dependency_inventory(elf, [service, lib])
        self.assertEqual(report["status"], "DIRECT_INVENTORY_ONLY")
        self.assertFalse(report["dependency_closure_verified"])
        elf[service]["custom_search_path"] = True
        self.assertEqual(extractor.hidl_dependency_inventory(elf, [service, lib])["status"],
                         "REVIEW_REQUIRED")
        elf[lib]["elf_type"] = "ET_EXEC"
        self.assertEqual(extractor.hidl_dependency_inventory(elf, [service, lib])["edges"][0]["status"],
                         "CANDIDATE_REJECTED")

    def test_vendor_dependency_walk_reads_transitive_snapshot_members(self):
        service = "bin/hw/android.hardware.gnss@1.0-service"
        self.put(service, b"service")
        self.put("lib/libone.so", b"one")
        self.put("lib/libtwo.so", b"two")
        self.put("lib/hw/liboutside.so", b"not searched")
        sha = self.make_image()

        def inspect(raw):
            deps = {b"service": ["libone.so"], b"one": ["libtwo.so"],
                    b"two": ["libone.so", "liboutside.so"]}
            sonames = {b"one": "libone.so", b"two": "libtwo.so"}
            return {"abi": "arm", "has_dynamic": True, "elf_type": "ET_DYN",
                    "needed": deps[raw], "soname": sonames.get(raw),
                    "custom_search_path": False}

        with mock.patch("r800_android_linker_audit.inspect", side_effect=inspect):
            report = extract(self.image, self.output, "vendor-identity", sha)
        walk = report["vendor_identity"]["vendor_dependency_walk"]
        self.assertEqual(walk["status"], "REVIEW_REQUIRED")
        self.assertEqual(walk["external_names"], ["liboutside.so"])
        self.assertEqual(walk["objects"]["vendor/lib/libtwo.so"]["depth"], 2)
        self.assertEqual(walk["objects"]["vendor/lib/libtwo.so"]["sha256"],
                         hashlib.sha256(b"two").hexdigest())
        self.assertEqual(len(walk["objects"]), 4)
        self.assertFalse(walk["budget_exhausted"])
        self.assertFalse(walk["dependency_closure_verified"])
        self.assertFalse((self.output/"vendor/lib/libone.so").exists())
        self.assertEqual(hashlib.sha256(self.image.read_bytes()).hexdigest(), sha)

    def test_vendor_dependency_walk_rejects_bad_names_and_bounds(self):
        service = "bin/hw/android.hardware.gnss@1.0-service"
        self.put(service, b"service")
        self.put("lib/libone.so", b"one")
        sha = self.make_image()
        def info(dep):
            return {"abi": "arm", "has_dynamic": True, "elf_type": "ET_DYN",
                    "needed": [dep], "soname": None, "custom_search_path": False}
        with mock.patch("r800_android_linker_audit.inspect", return_value=info("../private")):
            report = extract(self.image, self.output, "vendor-identity", sha)
        walk = report["vendor_identity"]["vendor_dependency_walk"]
        self.assertEqual(walk["edges"], [])
        self.assertIn("Invalid DT_NEEDED basename", walk["problems"][0])
        with mock.patch("r800_android_linker_audit.inspect", return_value=info("libone.so")), \
                mock.patch.object(extractor, "MAX_WALK_OBJECTS", 1):
            report = extract(self.image, self.root/"bounded", "vendor-identity", sha)
        walk = report["vendor_identity"]["vendor_dependency_walk"]
        self.assertTrue(walk["budget_exhausted"])
        self.assertEqual(walk["edges"][0]["status"], "NOT_INSPECTED")
        self.assertFalse(walk["safe_to_flash"])

    def test_system_dependency_candidates_use_verified_image(self):
        self.put("bin/hw/android.hardware.gnss@1.0-service", b"service")
        self.put("build.prop", b"ro.vndk.version=28\n")
        vendor_sha = self.make_image()
        vendor = self.image
        self.tree = self.root / "system-tree"
        self.tree.mkdir()
        self.image = self.root / "system.img"
        self.put("system/lib/vndk-28/libfixture.so", b"fixture")
        self.put("system/lib/libduplicate.so", b"duplicate")
        self.put("lib/libduplicate.so", b"duplicate")
        self.put("system/lib64/libmissing.so", b"wrong ABI directory")
        system_sha = self.make_image()

        def inspect(raw):
            return {"abi": "arm", "has_dynamic": True, "elf_type": "ET_DYN",
                    "needed": ["libfixture.so", "libduplicate.so", "libmissing.so"]
                    if raw == b"service" else [],
                    "soname": None, "custom_search_path": False}
        with mock.patch("r800_android_linker_audit.inspect", side_effect=inspect):
            report = extract(vendor, self.output, "vendor-identity", vendor_sha,
                             self.image, system_sha)
        result = report["vendor_identity"]["system_dependency_candidates"]
        rows = result["external_candidates"]
        self.assertEqual(rows["libfixture.so"]["status"], "CANDIDATE_ONLY")
        self.assertEqual(rows["libfixture.so"]["candidates"][0]["sha256"],
                         hashlib.sha256(b"fixture").hexdigest())
        self.assertEqual(rows["libduplicate.so"]["status"], "AMBIGUOUS")
        self.assertEqual(rows["libmissing.so"]["status"], "NOT_FOUND_IN_SELECTED_PATHS")
        self.assertEqual(result["status"], "REVIEW_REQUIRED")
        self.assertFalse(result["dependency_closure_verified"])
        self.assertFalse(result["apex_inspected"])
        self.assertEqual(hashlib.sha256(self.image.read_bytes()).hexdigest(), system_sha)
        self.assertEqual(hashlib.sha256(vendor.read_bytes()).hexdigest(), vendor_sha)
        self.assertFalse((self.output / "system").exists())
        with mock.patch("r800_android_linker_audit.inspect", side_effect=inspect):
            with self.assertRaisesRegex(ValueError, "SHA-256"):
                extract(vendor, self.root/"bad-system", "vendor-identity", vendor_sha,
                        self.image, "0"*64)

    def test_vendor_identity_conflicting_properties(self):
        self.put("build.prop", b"ro.product.vendor.model=One\n")
        self.put("default.prop", b"ro.product.vendor.model=Two\n")
        sha = self.make_image()
        report = extract(self.image, self.output, "vendor-identity", sha)
        self.assertEqual(report["vendor_identity"]["property_conflicts"],
                         ["ro.product.vendor.model"])
        self.assertFalse(report["safe_to_flash"])

    def test_ambiguous_glibc(self):
        self.put("lib/libc-2.24.so", b"one")
        self.put("usr/lib/libc-2.24.so", b"two")
        sha = self.make_image()
        report = extract(self.image, self.output, "tizen", sha)
        self.assertEqual(report["files"]["tizen/libc.so.6"]["status"], "AMBIGUOUS")
        self.assertFalse((self.output/"tizen/libc.so.6").exists())

    def test_guest_symlink_rejected(self):
        self.put("lib/other", b"synthetic")
        (self.tree/"lib/libc-2.24.so").symlink_to("other")
        sha = self.make_image()
        with self.assertRaisesRegex(ValueError,"regular donor"):
            extract(self.image, self.output, "tizen", sha)
        self.assertFalse(self.output.exists())

    def test_wrong_hash(self):
        self.make_image()
        with self.assertRaisesRegex(ValueError,"SHA-256"):
            extract(self.image, self.output, "tizen", "0"*64)

    def test_debugfs_uses_verified_private_snapshot(self):
        self.put("lib/libc-2.24.so", b"synthetic libc")
        sha = self.make_image()
        real_command = extractor.command
        paths = set()

        def observe(tool, image, request, cwd=None):
            self.assertNotEqual(image, self.image)
            self.assertEqual(hashlib.sha256(image.read_bytes()).hexdigest(), sha)
            paths.add(image)
            return real_command(tool, image, request, cwd=cwd)

        with mock.patch.object(extractor, "command", side_effect=observe):
            result = extract(self.image, self.output, "tizen", sha)
        self.assertEqual(len(paths), 1)
        self.assertFalse(next(iter(paths)).exists())
        self.assertTrue(result["snapshot_verified"])
        self.assertEqual((self.output/"tizen/libc.so.6").read_bytes(), b"synthetic libc")

    def test_donor_changed_after_snapshot_rejected(self):
        self.put("lib/libc-2.24.so", b"synthetic libc")
        sha = self.make_image()
        real_command = extractor.command
        changed = False

        def mutate(tool, image, request, cwd=None):
            nonlocal changed
            if not changed:
                with self.image.open("r+b") as stream:
                    stream.seek(0)
                    stream.write(b"changed")
                changed = True
            return real_command(tool, image, request, cwd=cwd)

        with mock.patch.object(extractor, "command", side_effect=mutate):
            with self.assertRaisesRegex(ValueError, "Donor image changed"):
                extract(self.image, self.output, "tizen", sha)
        self.assertTrue(changed)
        self.assertFalse(self.output.exists())

    def test_donor_symlink_rejected(self):
        sha = self.make_image()
        link = self.root/"donor-link.img"
        link.symlink_to(self.image)
        with self.assertRaisesRegex(ValueError, "regular donor image"):
            extract(link, self.output, "tizen", sha)
        self.assertFalse(self.output.exists())

if __name__=="__main__":
    unittest.main()
