#!/usr/bin/env python3
"""Publish only bytes matching a successful static GPS link audit (Linux host)."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import tempfile

from r800_android_userspace_preflight import read_regular
from r800_gps_donor_snapshot import DONORS, LIMIT


def publish(binary, report_path, manifest_path, output):
    report = json.loads(read_regular(report_path, 4 * 1024**2))
    manifest = json.loads(read_regular(manifest_path, 4096))
    if (report["status"] != "STATIC_GLIBC_CLOSURE_ONLY"
            or report["static_closure_pass"] is not True
            or report["safe_to_flash"] is not False
            or report["runtime_verified"] is not False
            or report["problems"] != []):
        raise ValueError("Static audit did not pass with NON-RELEASE scope")
    if (set(manifest["sha256"]) != set(DONORS)
            or report["donor_sha256"] != manifest["sha256"]):
        raise ValueError("Audit donor hashes do not match the snapshot manifest")
    data = read_regular(binary, LIMIT)
    digest = hashlib.sha256(data).hexdigest()
    if digest != report["sha256"]:
        raise ValueError("Binary does not match audited SHA-256")
    # Create a fresh inode from the audited bytes, not a hard link to
    # the mutable compiler output. The caller owns the private staging dir.
    fd, name = tempfile.mkstemp(prefix=".verified-", dir=binary.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fchmod(stream.fileno(), 0o755)
            os.fsync(stream.fileno())
        # Atomic no-replace publication; a directory or symlink is an error.
        os.link(name, output, follow_symlinks=False)
    finally:
        os.unlink(name)
    return digest


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ("binary", "report", "manifest", "output"):
        p.add_argument(name, type=Path)
    args = p.parse_args()
    try:
        digest = publish(args.binary, args.report, args.manifest, args.output)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        p.exit(2, "Publication rejected: " + str(exc) + "\n")
    print(digest + "  " + str(args.output))


if __name__ == "__main__":
    main()
