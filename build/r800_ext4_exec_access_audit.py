#!/usr/bin/env python3
"""Read-only advisory TE audit of console and selected ELF access.

Uses actual audited inode types. Selected ELF candidates may not all be
used by either process; console label and opener are assumptions, not
observed guest facts. Missing rules are reported, not auto-granted.
"""
import argparse
import json
from pathlib import Path
import subprocess
import tempfile

from r800_ext4_nosuid_policy_gate import allow
from r800_android_sepolicy_audit import audit, MAX_POLICY, sha
from r800_android_rootfs_preflight import snapshot
from r800_android_init_dependencies import regular
from r800_qemu_prelabeled_mounts import label_plan
from r800_qemu_readonly_disks import report

STATUS = "EXT4_EXEC_ACCESS_STATIC_ADVISORY_ONLY"
DOMAINS = ("init", "galwear_property_client")


def plan_checks(system, extra, runtime, profile):
    if profile not in ("stock", "fixture"):
        raise ValueError("Unknown access audit profile")
    labels = label_plan(system,extra,runtime)
    checks = {}
    def add(source,target,klass,perms,reason):
        for perm in perms:
            checks.setdefault((source,target,klass,perm),set()).add(reason)
    # Initial descriptors originate before policy load. Their actual
    # inode type and effective opener SID must be observed in the guest.
    domains = DOMAINS if profile == "fixture" else DOMAINS[:1]
    for domain in domains:
        add(domain,"kernel","fd",("use",),"assumed inherited kernel-opened console")
        add(domain,"console_device","chr_file",("read","write"),"assumed console inode type")
        add(domain,"rootfs","chr_file",("read","write"),"alternative rootfs console inode type")
    if profile == "fixture":
        for domain in domains:
            add(domain,"init","fd",("use",),"possible init-opened inherited descriptor")
            for path,context in labels.items():
                typ = context.split(":")[2]
                if path.startswith(("/system/lib64/","/apex/com.android.runtime/lib64/")) and path.endswith(".so"):
                    add(domain,typ,"file",("open","read","getattr","map","execute"),path)
                elif path in ("/system/bin/bootstrap/linker64","/apex/com.android.runtime/bin/linker64"):
                    add(domain,typ,"file",("open","read","getattr","map","execute"),path)
                elif path == "/system/bin/linker64":
                    info=system["verified_system_entries"][path[1:]]
                    if info["type"]=="symlink":
                        add(domain,typ,"lnk_file",("read","getattr"),path)
                    elif info["type"]=="regular":
                        add(domain,typ,"file",("open","read","getattr","map","execute"),path)
    if len(checks)>256:
        raise ValueError("Access query budget exceeded")
    return checks


def evaluate_blob(blob,system,extra,runtime,profile,sesearch="sesearch"):
    checks=plan_checks(system,extra,runtime,profile)
    results=[]
    with tempfile.TemporaryDirectory(prefix="galwear-exec-access-") as tmp:
        path=Path(tmp)/"sepolicy"
        path.write_bytes(blob)
        for (source,target,klass,perm),reasons in sorted(checks.items()):
            if source == target and klass == "fd":
                continue  # file_has_perm skips FD__USE for same SID.
            result=allow(path,sesearch,source,target,klass,perm)
            results.append({**result,"candidate_reasons":sorted(reasons)})
        if snapshot(path,MAX_POLICY)!=blob:
            raise ValueError("Policy changed during access audit")
    return {"status":STATUS,"profile":profile,"policy_sha256":sha(blob),
            "checks":results,
            "missing_unconditional_allow_count":sum(not r["unconditional_allow_found"] for r in results),
            "console_identity_assumed":True,"actual_fd_opener_sid_verified":False,
            "actual_library_resolution_verified":False,"full_avc_decision_proven":False,
            "runtime_access_tested":False,"safe_to_flash":False}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ("product-out","checkfc","system-report","context-report","runtime-report","report"):
        p.add_argument("--"+name,type=Path,required=True)
    p.add_argument("--profile",choices=("stock","fixture"),required=True)
    p.add_argument("--sesearch",default="sesearch")
    a=p.parse_args()
    try:
        audited=audit(a.product_out,a.checkfc)
        blob=snapshot(regular(a.product_out.resolve(strict=True),audited["policy_path"]),MAX_POLICY)
        policy=sha(blob)
        system=report(a.system_report,"ANDROID_SYSTEM_EXT4_SERVICE_STATIC_ONLY" if a.profile=="fixture" else
                      "ANDROID_SYSTEM_EXT4_LABELED_STATIC_ONLY")
        extra=report(a.context_report,"ANDROID_CONTEXT_PARTITIONS_STATIC_ONLY")
        runtime=report(a.runtime_report,"ANDROID_RUNTIME_APEX_PAYLOAD_PRESERVED_ONLY")
        if audited["policy_sha256"]!=policy or any(r["policy_sha256"]!=policy for r in (system,extra,runtime)):
            raise ValueError("Access audit policy identity mismatch")
        result=evaluate_blob(blob,system,extra,runtime,a.profile,a.sesearch)
        rc=0
    except (OSError,ValueError,KeyError,TypeError,AttributeError,RuntimeError,subprocess.SubprocessError) as exc:
        result={"status":"REJECT","reason":str(exc),"safe_to_flash":False}
        rc=2
    a.report.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
    print(result["status"])
    return rc

if __name__=="__main__":
    raise SystemExit(main())
