#!/usr/bin/env python3
"""GNSS readiness: local static checks and explicitly requested isolated glibc probe."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
from r800_gnss_ci import check as check_ci
from r800_gnss_donor_gate import run as run_donor

ROOT = Path(__file__).resolve().parents[1]
SHA = re.compile(r"[0-9a-f]{40}")
RUNTIME = ("donor_glibc_qemu", "android_hidl_registration", "effective_uid_gid",
           "shared_socket_runtime", "selinux_enforcing_access",
           "broadcom_transport", "physical_gnss_fix", "android_location_delivery")


def outcome(name, state, **evidence):
    return {"gate": name, "status": state, **evidence}


def git_state():
    def git(*args):
        return subprocess.check_output(["git", *args], cwd=ROOT, text=True, timeout=15).strip()
    sha = git("rev-parse", "HEAD")
    if not SHA.fullmatch(sha):
        raise ValueError("Invalid checkout SHA")
    return sha, not git("status", "--porcelain", "--untracked-files=all")


def static_gate(name, script, args, expected, *, bindings=None, timeout=120):
    if args is None:
        return outcome(name, "NOT_TESTED", reason="Required offline inputs absent")
    try:
        p = subprocess.run([sys.executable, str(ROOT/"build"/script), *map(str,args)],
                           cwd=ROOT, capture_output=True, timeout=timeout)
        raw = p.stdout
        data = json.loads(raw)
        if not isinstance(data, dict):
            raise ValueError("Expected JSON object")
        problems = data.get("problems")
        if not isinstance(problems,list) or not all(isinstance(v,str) for v in problems):
            raise ValueError("Missing explicit problem list")
        if data.get("safe_to_flash") is not False:
            raise ValueError("Missing non-release safety marker")
        passed = p.returncode == 0 and data.get("status") == expected and not problems
        if passed and bindings:
            for key, value in bindings.items():
                actual = data.get(key)
                if type(actual) is not type(value) or actual != value:
                    problems = problems + ["EVIDENCE_BINDING_MISMATCH:"+key]
            passed = not problems
        return outcome(name, "STATIC_PASS" if passed else "REVIEW_REQUIRED",
                       exit_code=p.returncode, report_status=data.get("status"),
                       report_sha256=hashlib.sha256(raw).hexdigest(),
                       problems=problems, detail=data)
    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
        return outcome(name,"ERROR",reason=str(exc))


def offline_gate(enabled, sha, clean):
    if not enabled:
        return outcome("offline_regression","NOT_TESTED",reason="Local execution not requested")
    if not clean:
        return outcome("offline_regression","BLOCKED",reason="Checkout is not clean")
    try:
        p = subprocess.run(["sh",str(ROOT/"build/r800_gps_offline_checks.sh")],
                           cwd=ROOT,capture_output=True,timeout=600)
        lines=p.stdout.decode("utf-8",errors="replace").splitlines()
        markers=(
            "SOURCE_SHA="+sha, "GPS_OFFLINE_COMPILE_GATE=PASS",
            "DONOR_LINK_VERIFIED=false", "QEMU_RUNTIME_VERIFIED=false",
            "GNSS_RUNTIME_VERIFIED=false", "safe_to_flash=false")
        after_sha, after_clean=git_state()
        marker_ok = all([line for line in lines if line.startswith(m.split("=", 1)[0]+"=")] == [m]
                        for m in markers)
        passed=(p.returncode==0 and marker_ok and after_sha==sha and after_clean)
        return outcome("offline_regression","PASS" if passed else "FAILED",
                       exit_code=p.returncode,source_sha=sha,
                       stdout_sha256=hashlib.sha256(p.stdout).hexdigest(),
                       stderr_sha256=hashlib.sha256(p.stderr).hexdigest(),
                       stdout_tail=lines[-40:],
                       stderr_tail=p.stderr.decode("utf-8",errors="replace").splitlines()[-40:])
    except (OSError,ValueError,subprocess.SubprocessError) as exc:
        return outcome("offline_regression","ERROR",reason=str(exc))


def ci_gate(enabled, sha):
    if not enabled:
        return outcome("exact_head_ci","NOT_TESTED",reason="Live GitHub metadata check not requested")
    try:
        detail=check_ci(sha)
        return outcome("exact_head_ci","PASS" if detail["status"]=="CI_METADATA_PASS"
                       else "REVIEW_REQUIRED",detail=detail)
    except (OSError,ValueError,subprocess.SubprocessError) as exc:
        return outcome("exact_head_ci","ERROR",reason=str(exc))


def donor_gate(sha,image,digest,ndk,output,run_qemu=False):
    if ndk is None:
        return outcome("donor_image_link","NOT_TESTED",reason="Local donor build not requested")
    try:
        result=run_donor(ROOT,sha,image,digest,ndk,output,run_qemu=run_qemu)
        return outcome("donor_image_link",result.pop("status"),**result)
    except (OSError,ValueError,subprocess.SubprocessError) as exc:
        return outcome("donor_image_link","ERROR",reason=str(exc))


def summarize(sha, clean, gates):
    all_gates=list(gates)+[outcome(name,"NOT_TESTED",reason="Separate runtime evidence required")
                           for name in RUNTIME if name!="donor_glibc_qemu"]
    # Only a fresh, validated donor pipeline may promote this one probe.
    # It does not execute the proprietary GNSS bridge or establish hardware ABI.
    donor=next((g for g in gates if g["gate"]=="donor_image_link"),None)
    probe=outcome("donor_glibc_qemu","NOT_TESTED",reason="Separate isolated glibc probe required")
    if donor and donor.get("qemu_requested") is True:
        passed=donor["status"]=="STATIC_PASS" and donor.get("qemu_probe_verified") is True
        probe=outcome("donor_glibc_qemu","PASS" if passed else "REVIEW_REQUIRED",
                      report_sha256=donor.get("report_sha256"),
                      scope="glibc version, pthread/TLS and dlopen only")
    all_gates.append(probe)
    return {"schema":"r800-gnss-readiness-v1","source_sha":sha,"checkout_clean":clean,
            "decision":"HOLD_RUNTIME_UNVERIFIED","gates":all_gates,
            "blockers":[g["gate"] for g in all_gates
                        if g["status"] not in ("PASS","STATIC_PASS")],
            "ci_verified":any(g["gate"]=="exact_head_ci" and g["status"]=="PASS"
                              for g in gates),
            "ci_logs_verified":False,"daemon_build_authorized":False,"safe_to_flash":False}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ("android-root","tizen-root","binary","libdir"):
        p.add_argument("--"+name,type=Path)
    p.add_argument("--tizen-image",type=Path)
    p.add_argument("--tizen-image-sha256")
    p.add_argument("--donor-ndk",type=Path)
    p.add_argument("--donor-output",type=Path)
    p.add_argument("--donor-qemu",action="store_true",help="Explicitly execute trusted glibc in isolated QEMU sandbox")
    p.add_argument("--run-offline",action="store_true")
    p.add_argument("--check-ci",action="store_true",help="Query live exact-head GitHub Actions metadata via gh")
    a=p.parse_args()
    try:
        sha,clean=git_state()
        if not clean:
            raise ValueError("Use a clean checkout; cannot bind dirty source to HEAD")
        if (a.binary is None) != (a.libdir is None):
            raise ValueError("--binary and --libdir must be supplied together")
        if (a.tizen_image is None) != (a.tizen_image_sha256 is None):
            raise ValueError("--tizen-image and --tizen-image-sha256 must be supplied together")
        if a.tizen_image_sha256 is not None and not re.fullmatch(r"[0-9a-f]{64}",a.tizen_image_sha256):
            raise ValueError("Expected lowercase image SHA-256")
        if (a.donor_ndk is None)!=(a.donor_output is None) or (a.donor_ndk is not None and a.tizen_image is None):
            raise ValueError("Donor link requires --donor-ndk, --donor-output and image inputs")
        if a.donor_qemu and a.donor_ndk is None:
            raise ValueError("--donor-qemu requires the complete donor link inputs")
        for root in (a.android_root,a.tizen_root):
            if root is not None and (not root.is_dir() or root.resolve()==Path("/")):
                raise ValueError("Use isolated, prepared offline roots")
        gates=[offline_gate(a.run_offline,sha,clean),ci_gate(a.check_ci,sha),
               static_gate("android_registration","r800_gnss_registration.py",
                           ["--root",a.android_root] if a.android_root else None,
                           "STATIC_GNSS_CONTRACT_ONLY"),
               static_gate("tizen_preflight","r800_tizen_gnss_preflight.py",
                           ["--root",a.tizen_root] if a.tizen_root else None,
                           "TIZEN_GNSS_STATIC_ONLY"),
               static_gate("tizen_image_closure","r800_gps_image_audit.py",
                           ["--image",a.tizen_image,"--sha256",a.tizen_image_sha256]
                           if a.tizen_image else None,"STATIC_IMAGE_GNSS_CLOSURE_ONLY",
                           bindings={"schema":"r800-gnss-image-audit-v1",
                                     "image_sha256":a.tizen_image_sha256,
                                     "snapshot_verified":True,
                                     "runtime_paths_verified":False,
                                     "donor_authenticity_verified":False,
                                     "hardware_interface_abi_verified":False,
                                     "gnss_runtime_verified":False},timeout=600),
               static_gate("ipc_layout","r800_gnss_ipc_layout.py",
                           ["--android-root",a.android_root,"--tizen-root",a.tizen_root]
                           if a.android_root and a.tizen_root else None,"STATIC_CANDIDATES_ONLY"),
               static_gate("glibc_link","r800_gps_link_gate.py",
                           ["--binary",a.binary,"--libdir",a.libdir] if a.binary and a.libdir else None,
                           "STATIC_GLIBC_CLOSURE_ONLY")]
        donor=donor_gate(sha,a.tizen_image,a.tizen_image_sha256,a.donor_ndk,a.donor_output,a.donor_qemu)
        donor["qemu_requested"]=a.donor_qemu
        gates.append(donor)
        end_sha,end_clean=git_state()
        if end_sha!=sha or not end_clean:
            raise ValueError("Checkout changed during audit")
        report=summarize(sha,clean,gates)
    except (OSError,ValueError,subprocess.SubprocessError) as exc:
        report={"schema":"r800-gnss-readiness-v1","decision":"REJECT_EVIDENCE",
                "reason":str(exc),"safe_to_flash":False,"daemon_build_authorized":False}
    print(json.dumps(report,indent=2,sort_keys=True))
    # HOLD always remains; nonzero only indicates failed or rejected checks.
    return 2 if report["decision"]=="REJECT_EVIDENCE" or any(
        g["status"] in ("FAILED","ERROR","REVIEW_REQUIRED","BLOCKED")
        for g in report.get("gates",[])) else 0


if __name__=="__main__":
    raise SystemExit(main())
