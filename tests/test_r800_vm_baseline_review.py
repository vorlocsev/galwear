"""Offline baseline chain: synthetic pinned reports and mocked structural review."""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"build"))
import r800_vm_baseline_review as vm
from r800_vm_package_lock import required_packages

SOURCE="a"*40


class BaselineTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root=Path(tmp.name)
        self.export=self.root/"export"
        self.export.mkdir()
        self.raw=vm.PROFILE.read_bytes()
        self.profile=json.loads(self.raw)
        self.profile_pin=hashlib.sha256(self.raw).hexdigest()
        required=required_packages(self.profile,"assembly")
        self.pkg={"schema":"galwear-r800-vm-package-lock-v1","source_sha":SOURCE,
                  "profile_sha256":self.profile_pin,"mode":"assembly",
                  "os":{"ID":"ubuntu","VERSION_ID":"24.04","architecture":"amd64"},
                  "status":"OBSERVED_PACKAGE_VERSIONS_ONLY","required_packages":required,
                  "packages":{n+":amd64":{"package":n,"architecture":"amd64","version":"1.0"}
                              for n in required},
                  "missing_required_packages":[],"foreign_arch_packages":[],
                  **{n:False for n in ("package_archive_bytes_verified","package_origin_verified",
                      "vm_isolation_verified","reproducible_build_verified","hardware_tested","safe_to_flash")}}
        self.bundle={}
        self.save("packages",self.pkg)
        self.decl={"schema":"galwear-r800-vm-export-declaration-v1","source_sha":SOURCE,
                   "profile_sha256":self.profile_pin,"package_lock_sha256":self.bundle["packages"][1],
                   "iso_sha256":"b"*64,"hypervisor":"fixture","hypervisor_version":"1",
                   "snapshot_id":"baseline",**{n:True for n in ("powered_off","donor_free",
                       "physical_passthrough_disabled","shared_host_folders_disabled","network_disconnected")}}
        self.save("declaration",self.decl)
        self.exp={"schema":"galwear-r800-vm-export-lock-v1","source_sha":SOURCE,
                  "status":"VM_EXPORT_BYTES_MATCH_DECLARED_BASELINE_ONLY","profile_sha256":self.profile_pin,
                  "package_lock_sha256":self.bundle["packages"][1],
                  "declaration_sha256":self.bundle["declaration"][1],"operator_declaration":self.decl,
                  "export":{"format":"OPAQUE_OVA","total_bytes":1024},
                  **{n:False for n in ("vm_contents_inspected","vm_boot_verified","vm_isolation_verified",
                       "donor_free_verified","reproducible_build_verified","hardware_tested","safe_to_flash")}}
        self.save("export",self.exp)
        self.structure={"schema":"galwear-r800-vm-export-structure-v1","source_sha":SOURCE,
                        "status":"SELECTED_OVF_VMDK_REFERENCES_MATCH_ONLY",
                        "export_lock_sha256":self.bundle["export"][1],
                        "structure":{"vmdk_descriptors":{"disk.vmdk":{}}},
                        **{n:False for n in ("grain_tables_verified","ovf_manifest_signature_verified",
                            "hypervisor_configuration_verified","guest_filesystem_verified",
                            "vm_boot_verified","donor_free_verified","hardware_tested","safe_to_flash")}}
        self.save("structure",self.structure)

    def save(self,name,data):
        path=self.root/(name+".json")
        raw=json.dumps(data,sort_keys=True).encode()
        path.write_bytes(raw)
        self.bundle[name]=(path,hashlib.sha256(raw).hexdigest())

    def records(self):
        return vm.review_records(self.raw,{"declaration":self.decl,"packages":self.pkg,
                                           "export":self.exp,"structure":self.structure},
                                 {n:v[1] for n,v in self.bundle.items()},SOURCE)

    def test_consistent_reports(self):
        self.assertEqual(self.records(),self.profile_pin)

    def test_export_wrong_declaration_pin(self):
        self.exp["declaration_sha256"]="0"*64
        with self.assertRaisesRegex(ValueError,"baseline report binding"):
            self.records()

    def test_structure_wrong_export_pin(self):
        self.structure["export_lock_sha256"]="0"*64
        with self.assertRaisesRegex(ValueError,"Structure report binding"):
            self.records()

    def test_unjustified_boot_claim(self):
        self.structure["vm_boot_verified"]=True
        with self.assertRaisesRegex(ValueError,"Structure report binding"):
            self.records()

    def test_package_missing(self):
        self.pkg["packages"].pop(next(iter(self.pkg["packages"])))
        with self.assertRaisesRegex(ValueError,"Saved package inventory requires review"):
            self.records()

    def test_recompute_not_build_ready(self):
        with patch.object(vm,"checkout_sha"), patch.object(vm,"review_structure",return_value=self.structure) as review:
            result=vm.review(self.export,self.bundle,SOURCE)
        review.assert_called_once_with(self.export,*self.bundle["export"],SOURCE)
        self.assertFalse(result["ready_to_build"])
        self.assertFalse(result["safe_to_flash"])
        self.assertIn("REAL_VM_BOOT",result["remaining_gates"])

    def test_recomputed_structure_differs(self):
        with patch.object(vm,"checkout_sha"), patch.object(vm,"review_structure",return_value={}):
            with self.assertRaisesRegex(ValueError,"Observed export structure differs"):
                vm.review(self.export,self.bundle,SOURCE)

    def test_report_modified(self):
        self.bundle["structure"][0].write_text("{}")
        with patch.object(vm,"checkout_sha"):
            with self.assertRaisesRegex(ValueError,"SHA-256 mismatch"):
                vm.review(self.export,self.bundle,SOURCE)


if __name__=="__main__":
    unittest.main()
