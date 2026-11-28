"""Synthetic package inventory and candidate profile tests."""
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"build"))
import r800_vm_package_lock as vm


class VmPackageLockTests(unittest.TestCase):
    def setUp(self):
        self.raw=b"installed\tpython3\tamd64\t3.12.3-0ubuntu2\ninstalled\tgit\tamd64\t1:2.43.0-1ubuntu7\ninstalled\tfonts-dejavu-core\tall\t2.37-8\n"
        self.profile=json.loads(vm.PROFILE.read_text())

    def test_installed_inventory(self):
        rows=vm.parse(self.raw)
        self.assertEqual(rows["git:amd64"]["version"],"1:2.43.0-1ubuntu7")
        self.assertEqual(vm.assess(rows,["python3","fonts-dejavu-core"]),
                         {"missing_required_packages":[],"foreign_arch_packages":[]})

    def test_residual_config_excluded(self):
        rows=vm.parse(self.raw+b"config-files\told\tamd64\t1.0\n")
        self.assertNotIn("old:amd64",rows)

    def test_partial_install_rejected(self):
        with self.assertRaisesRegex(ValueError,"Incomplete package state"):
            vm.parse(self.raw+b"half-configured\told\tamd64\t1.0\n")

    def test_duplicate_rejected(self):
        with self.assertRaisesRegex(ValueError,"Duplicate installed"):
            vm.parse(self.raw+self.raw)

    def test_missing_package(self):
        self.assertEqual(vm.assess(vm.parse(self.raw),["unshare-fixture"])["missing_required_packages"],
                         ["unshare-fixture"])

    def test_foreign_arch(self):
        rows=vm.parse(self.raw+b"installed\tlibc6\ti386\t2.39-1\n")
        self.assertEqual(vm.assess(rows,[])["foreign_arch_packages"],["libc6:i386"])

    def test_profiles_cumulative(self):
        a=set(vm.required_packages(self.profile,"assembly"))
        c=set(vm.required_packages(self.profile,"compilation"))
        g=set(vm.required_packages(self.profile,"guest-tests"))
        self.assertTrue(a<c<g)
        self.assertIn("e2fsprogs",a)
        self.assertIn("gcc-arm-linux-gnueabi",c)
        self.assertIn("bubblewrap",g)

    def test_profile_safety(self):
        iso=self.profile["isolation"]
        self.assertFalse(iso["physical_disk_passthrough"])
        self.assertFalse(iso["usb_passthrough"])
        self.assertFalse(iso["shared_host_folders"])
        self.assertEqual(iso["network_during_build"],"disconnected")
        self.assertFalse(self.profile["safe_to_flash"])


if __name__=="__main__":
    unittest.main()
