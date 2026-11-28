#!/usr/bin/env python3
"""Build and stage a minimal GPSBridge runtime with exact local library pins.

The Debian reference is never a Tizen replacement. The local Tizen scope
also does not establish authenticity, daemon/plugin availability or GNSS.
Only the host compiler is run; no guest ELF is executed.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

from r800_gps_donor_snapshot import create, verify, DONORS, LIMIT
from r800_gps_link_gate import audit, audit_donors
from r800_android_userspace_preflight import read_regular
from r800_graphics_donor_binding import checkout_sha
from r800_extract_super import require
from r800_verify_tizen_stage import unique_keys

SCOPES = ("DEBIAN_REFERENCE_NOT_TIZEN", "LOCAL_TIZEN_CANDIDATE")


def build(libdir, pins, ndk, output, source_sha, scope, xtra_abi=0):
    checkout_sha(source_sha)
    repo = Path(__file__).resolve().parents[1]
    require(scope in SCOPES and type(xtra_abi) is int and xtra_abi in (0, 1, 2),
            "Unsupported runtime scope or XTRA ABI")
    require(isinstance(pins, dict) and set(pins) == set(DONORS) and
            all(isinstance(pin, str) and re.fullmatch(r"[0-9a-f]{64}", pin)
                for pin in pins.values()), "Four explicit library SHA-256 pins required")
    libdir = Path(libdir).resolve(strict=True)
    ndk = Path(ndk).resolve(strict=True)
    output = Path(output).absolute()
    require(not output.exists() and not output.is_symlink() and
            not any(output.resolve().is_relative_to(root) for root in (repo, libdir, ndk)),
            "Fresh output outside input trees required")
    with tempfile.TemporaryDirectory(dir=output.parent, prefix="r800-runtime-") as tmp:
        work = Path(tmp)
        snapshot = work/"libs"
        snapshot.mkdir(mode=0o700)
        observed = create(libdir, snapshot)
        require(observed["sha256"] == pins, "Runtime library pin mismatch")
        verify(libdir, snapshot, observed)
        pre = audit_donors(snapshot)
        require(pre["status"] == "DONOR_STATIC_CLOSURE_ONLY" and
                pre["static_closure_pass"] is True and pre["donor_sha256"] == pins,
                "Runtime library static closure failed")
        stage = work/"result"
        stage.mkdir()
        # Reference output cannot occupy the deployment-oriented Tizen paths.
        if scope == "DEBIAN_REFERENCE_NOT_TIZEN":
            base = "reference-runtime"
            libpath, bridgepath = base+"/lib", base+"/gpsbridge"
        else:
            libpath, bridgepath = "r800dev/tzlite/lib", "r800dev/gpsbridge"
        target = stage/bridgepath
        target.parent.mkdir(parents=True, exist_ok=True)
        env = dict(os.environ)
        env.update(R800_XTRA_ABI=str(xtra_abi), R800_TIZEN_ARCHIVE="", R800_HOST_SNAPSHOT="0")
        for name in ("LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT", "ENV", "BASH_ENV"):
            env.pop(name, None)
        subprocess.run(["sh", str(repo/"src/tools/gps/build.sh"), str(ndk),
                        str(snapshot), str(target)], env=env, check=True, timeout=300)
        post = audit(target, snapshot)
        require(post["status"] == "STATIC_GLIBC_CLOSURE_ONLY" and
                post["static_closure_pass"] is True and post["donor_sha256"] == pins,
                "GPSBridge static link audit failed")
        rows = {}
        for name in DONORS:
            raw = read_regular(snapshot/name, LIMIT)
            sha = hashlib.sha256(raw).hexdigest()
            require(sha == pins[name], "Runtime library changed")
            path = stage/libpath/name
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("xb") as stream:
                stream.write(raw)
            path.chmod(0o644)
            rows[libpath+"/"+name] = {"sha256": sha, "bytes": len(raw), "mode": "0o644"}
        binary = read_regular(target, LIMIT)
        require(hashlib.sha256(binary).hexdigest() == post["sha256"], "GPSBridge changed after link")
        target.chmod(0o755)
        rows[bridgepath] = {"sha256": post["sha256"], "bytes": len(binary), "mode": "0o755"}
        verify(libdir, snapshot, observed)
        checkout_sha(source_sha)
        report = {"schema": "galwear-r800-runtime-layer-v1",
                  "status": "GPS_RUNTIME_SUBSET_STAGED_ONLY", "scope": scope,
                  "source_sha": source_sha, "xtra_abi": xtra_abi,
                  "library_sha256": pins, "gpsbridge_sha256": post["sha256"], "files": rows,
                  "missing_inputs": ["Tizen lhd/gpsd/sensord and ELF dependency closure",
                                     "Tizen configuration and plugins", "device firmware"],
                  "tizen_donor_verified": False, "full_runtime_built": False,
                  "guest_execution_verified": False, "gnss_runtime_verified": False,
                  "hardware_tested": False, "safe_to_flash": False}
        (stage/"runtime-layer-evidence.json").write_text(json.dumps(report, indent=2, sort_keys=True)+"\n")
        require(not output.exists() and not output.is_symlink(), "Output already exists")
        os.rename(stage, output)
    return report


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--libdir", type=Path, required=True)
    p.add_argument("--pins", type=Path, required=True, help="JSON object mapping four filenames to SHA-256")
    p.add_argument("--ndk", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--source-sha", required=True)
    p.add_argument("--scope", required=True, choices=SCOPES)
    p.add_argument("--xtra-abi", type=int, choices=(0, 1, 2), default=0)
    a = p.parse_args()
    pins = json.loads(read_regular(a.pins, 4096), object_pairs_hook=unique_keys)
    report = build(a.libdir, pins, a.ndk, a.output, a.source_sha, a.scope, a.xtra_abi)
    print(report["status"], report["scope"], len(report["files"]), "files; safe_to_flash=false")


if __name__ == "__main__":
    main()
