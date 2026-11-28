#!/usr/bin/env python3
"""Combine pinned VM profile, packages, declaration, export and structure.

Read-only offline review; no VM boot/import, donor access or build authorization.
The export is hashed twice by the structural reviewer, not once per report.
"""
import argparse
import hashlib
import json
from pathlib import Path

from r800_android_userspace_preflight import read_regular
from r800_extract_super import require
from r800_graphics_donor_binding import checkout_sha
from r800_verify_tizen_stage import unique_keys
from r800_vm_export_lock import PROFILE, MAX_REPORT, pinned, metadata, package_review
from r800_vm_export_structure import review as review_structure

ROLES=("declaration","packages","export","structure")


def review_records(profile_raw,records,pins,source):
    profile=json.loads(profile_raw,object_pairs_hook=unique_keys)
    profile_pin=hashlib.sha256(profile_raw).hexdigest()
    require(profile.get("schema")=="galwear-r800-vm-profile-v1" and
            profile.get("status")=="CANDIDATE_PROFILE_ONLY" and
            all(profile.get(k) is False for k in ("vm_created","hardware_tested","safe_to_flash")),
            "Unexpected VM profile scope")
    require(profile["isolation"]=={"dedicated_vm":True,"physical_disk_passthrough":False,
            "usb_passthrough":False,"shared_host_folders":False,"shared_clipboard":False,
            "network_during_provisioning":"NAT","network_during_build":"disconnected",
            "snapshot_before_donors":True},"Unexpected candidate isolation profile")
    decl,pkg,export,structure=(records[n] for n in ROLES)
    metadata(decl,source,profile_pin,pins["packages"])
    package_review(pkg,profile,profile_pin,source)
    require(export.get("schema")=="galwear-r800-vm-export-lock-v1" and
            export.get("source_sha")==source and
            export.get("status")=="VM_EXPORT_BYTES_MATCH_DECLARED_BASELINE_ONLY" and
            export.get("profile_sha256")==profile_pin and
            export.get("package_lock_sha256")==pins["packages"] and
            export.get("declaration_sha256")==pins["declaration"] and
            export.get("operator_declaration")==decl and
            all(export.get(k) is False for k in ("vm_contents_inspected","vm_boot_verified",
                 "vm_isolation_verified","donor_free_verified","reproducible_build_verified",
                 "hardware_tested","safe_to_flash")),"Export baseline report binding mismatch")
    require(structure.get("schema")=="galwear-r800-vm-export-structure-v1" and
            structure.get("source_sha")==source and
            structure.get("export_lock_sha256")==pins["export"] and
            structure.get("status")=="SELECTED_OVF_VMDK_REFERENCES_MATCH_ONLY" and
            all(structure.get(k) is False for k in ("grain_tables_verified",
                "ovf_manifest_signature_verified","hypervisor_configuration_verified",
                "guest_filesystem_verified","vm_boot_verified","donor_free_verified",
                "hardware_tested","safe_to_flash")),"Structure report binding mismatch")
    return profile_pin


def review(root,bundle,source):
    checkout_sha(source)
    root=Path(root).absolute()
    require(set(bundle)==set(ROLES),"Complete baseline report bundle required")
    paths={n:Path(bundle[n][0]).absolute() for n in ROLES}
    require(len(set(paths.values()))==len(ROLES) and
            all(not p.is_relative_to(root) for p in paths.values()),
            "Distinct evidence files outside VM export required")
    pins={n:bundle[n][1] for n in ROLES}
    profile_raw=read_regular(PROFILE,1024*1024)
    rows={n:pinned(paths[n],pins[n],MAX_REPORT) for n in ROLES}
    records={n:row[1] for n,row in rows.items()}
    profile_pin=review_records(profile_raw,records,pins,source)
    observed=review_structure(root,paths["export"],pins["export"],source)
    require(observed==records["structure"],"Observed export structure differs from pinned report")
    require(read_regular(PROFILE,1024*1024)==profile_raw and
            all(pinned(paths[n],pins[n],MAX_REPORT)[0]==rows[n][0] for n in ROLES),
            "Baseline evidence changed during review")
    checkout_sha(source)
    return {"schema":"galwear-r800-vm-baseline-review-v1","source_sha":source,
            "status":"BASELINE_EXPORT_AND_SAVED_REPORTS_MATCH_ONLY",
            "profile_sha256":profile_pin,"report_sha256":pins,
            "package_mode":records["packages"]["mode"],
            "package_count":len(records["packages"]["packages"]),
            "export_format":records["export"]["export"]["format"],
            "export_bytes":records["export"]["export"]["total_bytes"],
            "virtual_disk_count":len(observed["structure"]["vmdk_descriptors"]),
            "checks":{"profile_and_declaration_match":True,"saved_package_inventory_match":True,
                      "export_bytes_rehashed":True,"selected_structure_recomputed":True},
            "remaining_gates":["REAL_VM_BOOT","LIVE_VM_ENVIRONMENT_AND_RUNTIME_PROBES",
                "HYPERVISOR_ISOLATION","GUEST_FILESYSTEM_AND_DONOR_FREE_REVIEW",
                "LOCAL_DONOR_ACCEPTANCE","DEVELOPMENT_BUILD"],
            "live_package_inventory_verified":False,"vm_boot_verified":False,
            "vm_isolation_verified":False,"donor_free_verified":False,
            "reproducible_build_verified":False,"ready_to_build":False,
            "hardware_tested":False,"safe_to_flash":False}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--export-dir",type=Path,required=True)
    p.add_argument("--source-sha",required=True)
    for name in ROLES:
        p.add_argument("--"+name,type=Path,required=True)
        p.add_argument("--"+name+"-sha256",required=True)
    a=p.parse_args()
    bundle={n:(getattr(a,n),getattr(a,n+"_sha256")) for n in ROLES}
    print(json.dumps(review(a.export_dir,bundle,a.source_sha),indent=2,sort_keys=True))


if __name__=="__main__":
    main()
