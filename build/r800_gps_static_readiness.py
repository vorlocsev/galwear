#!/usr/bin/env python3
"""Aggregate matching GPS Bridge static evidence; never authorize flashing."""
import argparse
import hashlib
import json
from pathlib import Path
import re

from r800_android_userspace_preflight import read_regular
from r800_gps_donor_snapshot import DONORS
from r800_gps_link_gate import audit as link_audit
from r800_gps_repeatability import normalize_argv
from r800_gps_provenance import collect
from r800_pack_tizen_stage import verify_archive
from r800_tizen_gnss_preflight import check as gnss_check
from r800_verify_tizen_stage import unique_keys

LIMIT = 4 * 1024**2
RUNTIME_FLAGS = ("runtime_mounts_verified", "socket_permissions_verified",
                 "bridge_protocol_verified", "hardware_interface_abi_verified",
                 "hal_registered", "gnss_fix_verified", "safe_to_flash")


def digest(value):
    return isinstance(value, str) and re.fullmatch(r"[a-f0-9]{64}", value) is not None


def read_record(path):
    value = json.loads(read_regular(path, LIMIT), object_pairs_hook=unique_keys)
    if not isinstance(value, dict):
        raise ValueError("Expected evidence object")
    return value


def evaluate(link, preflight, archive, build, repeat, current_inputs):
    problems = []
    def require(condition, label):
        if not condition:
            problems.append(label)

    hashes = link.get("donor_sha256")
    require(link.get("status") == "STATIC_GLIBC_CLOSURE_ONLY"
            and link.get("static_closure_pass") is True
            and link.get("problems") == []
            and link.get("runtime_verified") is False
            and link.get("safe_to_flash") is False
            and digest(link.get("sha256"))
            and isinstance(hashes, dict) and set(hashes) == set(DONORS)
            and all(digest(v) for v in hashes.values()), "LINK_AUDIT")
    require(preflight.get("status") == "TIZEN_GNSS_STATIC_ONLY"
            and preflight.get("strict_4k_page_review") is True
            and preflight.get("problems") == []
            and preflight.get("closure_problems") == []
            and all(preflight.get(k) is False for k in RUNTIME_FLAGS),
            "GNSS_PREFLIGHT")
    bindings = archive.get("donor_bindings")
    require(archive.get("status") == "TIZEN_ELF_ARCHIVE_STATIC_ONLY"
            and archive.get("strict_4k_page_review") is True
            and archive.get("runtime_verified") is False
            and archive.get("safe_to_flash") is False
            and digest(archive.get("sha256"))
            and isinstance(bindings, dict) and set(bindings) == set(DONORS)
            and isinstance(hashes, dict)
            and all(isinstance(v, dict) and v.get("sha256") == hashes.get(k)
                    for k, v in bindings.items()), "ARCHIVE_DONORS")
    inputs = build.get("inputs")
    require(build.get("schema") == "galwear-r800-gps-evidence-v1"
            and build.get("safe_to_flash") is False
            and build.get("signed_attestation") is False
            and build.get("binary_sha256") == link.get("sha256")
            and build.get("donor_sha256") == hashes
            and build.get("tizen_archive") == archive
            and inputs == current_inputs
            and isinstance(inputs, dict)
            and inputs.get("schema") == "galwear-r800-gps-inputs-v1"
            and inputs.get("safe_to_flash") is False
            and inputs.get("signed_attestation") is False
            and build.get("inputs_sha256") == hashlib.sha256(
                json.dumps(inputs, sort_keys=True).encode()).hexdigest(),
            "BUILD_PROVENANCE")
    expected = None
    if isinstance(inputs, dict):
        try:
            expected = {"binary_sha256": link["sha256"], "donor_sha256": hashes,
                        "input_fingerprints": inputs["inputs"],
                        "compiler_argv": normalize_argv(inputs["argv"]),
                        "tizen_archive": archive}
        except (KeyError, ValueError, TypeError, IndexError):
            pass
    require(repeat.get("schema") == "galwear-r800-gps-repeatability-v1"
            and repeat.get("status") == "LOCAL_REPEATABILITY_PASS"
            and repeat.get("differences") == []
            and repeat.get("independent_hosts_tested") is False
            and repeat.get("runtime_verified") is False
            and repeat.get("safe_to_flash") is False
            and expected is not None and repeat.get("runs") == [expected, expected]
            and type(repeat.get("xtra_abi")) is int
            and repeat["xtra_abi"] in (0, 1, 2)
            and "-DR800_XTRA_ABI=" + str(repeat["xtra_abi"]) in expected["compiler_argv"],
            "LOCAL_REPEATABILITY")
    return {"schema": "galwear-r800-gps-static-readiness-v1",
            "status": "GPS_STATIC_EVIDENCE_MATCH" if not problems else "REVIEW_REQUIRED",
            "problems": problems, "static_evidence_match": not problems,
            "binary_sha256": link.get("sha256"), "archive_sha256": archive.get("sha256"),
            "signed_attestation": False, "runtime_verified": False,
            "hardware_verified": False, "safe_to_flash": False}


def check(binary, libdir, donor_root, archive_path, build_path, repeat_path, root, ndk):
    build = read_record(build_path)
    repeat = read_record(repeat_path)
    link = link_audit(binary, libdir)
    preflight = gnss_check(donor_root, strict_pages=True)
    archive = verify_archive(archive_path, donor_hashes=link["donor_sha256"],
                             required_files=preflight["closure_sha256"])
    current = collect(root, ndk, build["inputs"]["argv"])
    return evaluate(link, preflight, archive, build, repeat, current)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("binary", "libdir", "donor-root", "archive", "build-evidence",
                 "repeatability", "root", "ndk"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    try:
        report = check(args.binary, args.libdir, args.donor_root, args.archive,
                       args.build_evidence, args.repeatability, args.root, args.ndk)
    except (OSError, ValueError, TypeError, KeyError, IndexError, RecursionError) as exc:
        report = {"status": "REVIEW_REQUIRED", "problems": [str(exc)],
                  "static_evidence_match": False, "safe_to_flash": False,
                  "runtime_verified": False}
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["status"] == "GPS_STATIC_EVIDENCE_MATCH" else 2


if __name__ == "__main__":
    raise SystemExit(main())
