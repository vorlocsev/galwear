#!/usr/bin/env python3
"""Bind local Tizen glibc extraction, static link and optional QEMU to exact inputs."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

from r800_extract_ext4 import extract
from r800_gps_link_gate import DONORS, audit, elf
from r800_stage_gps_donors import read_source
from r800_gnss_readiness import ROOT, git_state


def verify_extraction(report, libdir, expected_sha):
    if (report.get("status") != "EXT4_DONOR_EXTRACTION_ONLY"
            or report.get("profile") != "gps-glibc"
            or report.get("image_sha256") != expected_sha
            or report.get("snapshot_verified") is not True
            or report.get("safe_to_flash") is not False
            or report.get("missing_or_ambiguous") != []):
        raise ValueError("Incomplete or mismatched extraction evidence")
    files = report.get("files")
    if not isinstance(files, dict) or set(files) != {"tizen/"+n for n in DONORS}:
        raise ValueError("Unexpected extraction members")
    if libdir.is_symlink() or not libdir.is_dir():
        raise ValueError("Expected private extracted library directory")
    hashes = {}
    for name in DONORS:
        item = files["tizen/"+name]
        raw = read_source(libdir/name)
        digest = hashlib.sha256(raw).hexdigest()
        if (item.get("status") != "EXTRACTED" or item.get("sha256") != digest
                or item.get("bytes") != len(raw)):
            raise ValueError("Extracted file evidence mismatch: "+name)
        hashes[name] = digest
    return hashes


def unique_marker(log, expected):
    key = expected.partition("=")[0]
    return [line for line in log.splitlines()
            if line.partition("=")[0].strip() == key] == [expected]


def execute_step(command, workdir, log_path, seconds):
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", LC_ALL="C")
    with log_path.open("xb") as stream:
        proc = subprocess.run(command, cwd=workdir, env=env, stdout=stream,
                              stderr=subprocess.STDOUT, timeout=seconds)
    raw = log_path.read_bytes()
    return {"exit_code": proc.returncode, "log_sha256": hashlib.sha256(raw).hexdigest(),
            "log_file": log_path.name}, raw.decode("utf-8", errors="replace")


def run(image, expected_sha, ndk, out, run_qemu=False):
    if not re.fullmatch(r"[0-9a-f]{64}", expected_sha):
        raise ValueError("Provide expected SHA-256 from a trusted source")
    if os.getuid() == 0:
        raise ValueError("Run as an unprivileged user")
    source_sha, clean = git_state()
    if not clean:
        raise ValueError("Use a clean source checkout")
    image = image.absolute()
    ndk = ndk.resolve(strict=True)
    out = out.parent.resolve(strict=True)/out.name
    if out == ROOT or ROOT in out.parents:
        raise ValueError("Evidence output must be outside checkout")
    out.mkdir(mode=0o700)
    report = {"schema":"r800-tizen-glibc-check-v1", "source_sha":source_sha,
              "image_sha256":expected_sha, "status":"REVIEW_REQUIRED",
              "gates":{}, "donor_authenticity_verified":False,
              "gnss_runtime_verified":False, "safe_to_flash":False}
    gates = report["gates"]
    try:
        with tempfile.TemporaryDirectory(prefix="r800-donor-", dir=out) as scratch:
            work = Path(scratch)
            dest = work/"extracted"
            extracted = extract(image, dest, "gps-glibc", expected_sha)
            libdir = dest/"tizen"
            hashes = verify_extraction(extracted, libdir, expected_sha)
            gates["extraction"] = {"status":"PASS", "donor_sha256":hashes,
                                   "detail":extracted}
            for name in DONORS:
                if elf(read_source(libdir/name))["soname"] != name:
                    raise ValueError("Unexpected donor SONAME: "+name)
            binary = work/"gpsbridge"
            # Explicitly disable daemon credentials and XTRA for this static-only build.
            env = dict(os.environ)
            command = ["env","R800_XTRA_ABI=0","R800_GPS_PEER_UID=-1",
                       "R800_GPS_PEER_GID=-1","sh",str(ROOT/"src/tools/gps/build.sh"),
                       str(ndk),str(libdir),str(binary)]
            evidence, _ = execute_step(command, ROOT, out/"link.log", 300)
            gates["link"] = dict(evidence, status="FAILED")
            if evidence["exit_code"]:
                raise ValueError("Donor bridge build failed; inspect link.log")
            static = audit(binary, libdir)
            gates["link"]["detail"] = static
            if (static.get("status") != "STATIC_GLIBC_CLOSURE_ONLY"
                    or static.get("static_closure_pass") is not True
                    or static.get("problems") != []
                    or static.get("donor_sha256") != hashes
                    or static.get("safe_to_flash") is not False):
                raise ValueError("Static closure not confirmed")
            gates["link"]["status"] = "STATIC_PASS"
            gates["qemu"] = {"status":"NOT_TESTED"}
            if run_qemu:
                evidence, log = execute_step(
                    ["sh",str(ROOT/"build/r800_gps_glibc_qemu.sh"),str(ndk),str(libdir)],
                    ROOT,out/"qemu.log",300)
                gates["qemu"] = dict(evidence,status="FAILED")
                if evidence["exit_code"] or not all(unique_marker(log,m) for m in (
                    "GLIBC_2_24=PASS","PTHREAD_TLS=PASS","DLOPEN_DLSYM=PASS",
                    "R800_GLIBC_QEMU_PROBE=PASS","QEMU_USER_ONLY=PASS",
                    "GNSS_RUNTIME_VERIFIED=false","safe_to_flash=false")):
                    raise ValueError("QEMU probe not confirmed; inspect qemu.log")
                gates["qemu"]["status"]="PASS"
            if verify_extraction(extracted,libdir,expected_sha)!=hashes:
                raise ValueError("Donors changed")
            if git_state()!=(source_sha,True):
                raise ValueError("Source checkout changed")
        report["status"]="DONOR_GLIBC_PROBE_ONLY" if run_qemu else "STATIC_DONOR_LINK_ONLY"
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        report["reason"]=str(exc)
    (out/"report.json").write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    return report


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ("image","ndk","output"):
        p.add_argument("--"+name,type=Path,required=True)
    p.add_argument("--sha256",required=True)
    p.add_argument("--run-qemu",action="store_true",
                   help="Execute trusted local glibc only in the existing unprivileged sandbox")
    a=p.parse_args()
    try:
        report=run(a.image,a.sha256,a.ndk,a.output,a.run_qemu)
    except (OSError,ValueError,subprocess.SubprocessError) as exc:
        report={"status":"REVIEW_REQUIRED","reason":str(exc),"safe_to_flash":False}
    print(json.dumps(report,indent=2,sort_keys=True))
    return 2 if report["status"]=="REVIEW_REQUIRED" else 0


if __name__=="__main__":
    raise SystemExit(main())
