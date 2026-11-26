#!/usr/bin/env python3
"""Bind a local ARM32 QEMU glibc probe transcript to its exact inputs."""
import argparse
import hashlib
import json
from pathlib import Path
import re

DONORS = ("libc.so.6", "libdl.so.2", "libpthread.so.0", "ld-linux.so.3")
LABELS = (*DONORS, "probe", "plugin", "qemu", "bwrap")
MARKERS = ("GLIBC_2_24", "MAIN_TLS", "PTHREAD_TLS", "DLOPEN",
           "DLSYM", "DLCLOSE", "DLOPEN_DLSYM", "R800_GLIBC_QEMU_PROBE")
MAX_LOG = 1024**2


def valid_inventory(value):
    return (isinstance(value, dict) and set(value) == set(LABELS)
            and all(isinstance(v, str) and re.fullmatch(r"[a-f0-9]{64}", v)
                    for v in value.values()))


def evaluate(log, rc, before, after, audit):
    if not isinstance(log, bytes) or len(log) > MAX_LOG or type(rc) is not int or not 0 <= rc <= 255:
        raise ValueError("Invalid probe transcript or exit status")
    text = log.decode("utf-8", errors="strict")
    lines = text.splitlines()
    expected = [name + "=PASS" for name in MARKERS]
    markers = [line for line in lines if line in expected or
               any(line.startswith(name + "=") for name in MARKERS)]
    prefix = []
    for line, want in zip(markers, expected):
        if line != want:
            break
        prefix.append(line[:-5])
    problems = []
    if not valid_inventory(before) or not valid_inventory(after) or before != after:
        problems.append("INPUT_IDENTITY")
    if (not valid_inventory(before) or not isinstance(audit, dict)
            or audit.get("status") != "STATIC_GLIBC_CLOSURE_ONLY"
            or audit.get("static_closure_pass") is not True
            or audit.get("safe_to_flash") is not False
            or audit.get("runtime_verified") is not False
            or audit.get("problems") != []
            or audit.get("sha256") != before["probe"]
            or audit.get("donor_sha256") != {name: before[name] for name in DONORS}):
        problems.append("STATIC_LINK_EVIDENCE")
    if markers != expected[:len(markers)]:
        problems.append("MARKER_SEQUENCE")
    if rc != 0:
        problems.append("TIMEOUT_OR_KILLED" if rc in (124, 137) else "NONZERO_EXIT")
    if lines != expected:
        problems.append("INCOMPLETE_OR_UNEXPECTED_TRANSCRIPT")
    status = "QEMU_GLIBC_PROBE_PASS" if not problems else "QEMU_GLIBC_PROBE_REVIEW_REQUIRED"
    return {"schema": "galwear-r800-glibc-qemu-evidence-v1", "status": status,
            "exit_code": rc, "observed_ordered_markers": prefix,
            "checks": {name: name in prefix for name in MARKERS},
            "problems": problems, "inputs_sha256": before,
            "log_sha256": hashlib.sha256(log).hexdigest(),
            "scope": "local ARM32 synthetic probe only",
            "gnss_runtime_verified": False, "hardware_verified": False,
            "signed_attestation": False, "safe_to_flash": False}


def capture(root, qemu, bwrap):
    from r800_android_userspace_preflight import read_regular
    paths = {name: root / "lib" / name for name in DONORS}
    paths.update(probe=root / "probe", plugin=root / "probe_plugin.so",
                 qemu=qemu.resolve(strict=True), bwrap=bwrap.resolve(strict=True))
    return {name: hashlib.sha256(read_regular(path, 128 * 1024**2)).hexdigest()
            for name, path in paths.items()}


def load_json(path):
    from r800_android_userspace_preflight import read_regular
    return json.loads(read_regular(path, 4 * 1024**2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    snap = sub.add_parser("capture")
    for name in ("root", "qemu", "bwrap"):
        snap.add_argument("--" + name, type=Path, required=True)
    review = sub.add_parser("review")
    for name in ("before", "after", "audit", "log"):
        review.add_argument("--" + name, type=Path, required=True)
    review.add_argument("--exit-code", type=int, required=True)
    args = parser.parse_args()
    try:
        if args.command == "capture":
            report = capture(args.root, args.qemu, args.bwrap)
        else:
            with args.log.open("rb") as stream:
                raw = stream.read(MAX_LOG + 1)
            report = evaluate(raw, args.exit_code, load_json(args.before),
                              load_json(args.after), load_json(args.audit))
    except (OSError, ValueError, TypeError, KeyError) as exc:
        report = {"status": "QEMU_GLIBC_PROBE_REVIEW_REQUIRED",
                  "problems": [str(exc)], "safe_to_flash": False}
    print(json.dumps(report, sort_keys=True))
    return 0 if (valid_inventory(report) if args.command == "capture"
                 else report["status"] == "QEMU_GLIBC_PROBE_PASS") else 2


if __name__ == "__main__":
    raise SystemExit(main())
