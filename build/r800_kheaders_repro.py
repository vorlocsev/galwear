#!/usr/bin/env python3
"""Normalize the existing Galwear IKHEADERS dummy archive in a disposable tree."""
import argparse
from pathlib import Path

EXPECTED = b'#!/bin/bash\ntouch /tmp/dummy\ntar -cJf "$1" -C /tmp dummy\nexit 0\n'
REPLACEMENT = b'''#!/bin/bash
set -e
# Preserve the existing placeholder contract, not real kernel headers.
python3 - "$1" <<'PY'
import sys
import tarfile
with tarfile.open(sys.argv[1], "w:xz", format=tarfile.USTAR_FORMAT, preset=6) as archive:
    member = tarfile.TarInfo("dummy")
    member.size = 0
    member.mtime = 0
    member.uid = member.gid = 0
    member.uname = member.gname = ""
    member.mode = 0o644
    archive.addfile(member)
PY
'''


def normalize(data):
    if data != EXPECTED:
        raise ValueError("Unexpected patched kheaders generator")
    return REPLACEMENT


def apply(root):
    path = root / "kernel/gen_kheaders.sh"
    if path.is_symlink() or not path.is_file():
        raise ValueError("Missing or symlinked kheaders generator")
    path.write_bytes(normalize(path.read_bytes()))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path)
    args = parser.parse_args()
    apply(args.source)
    print("Normalized existing IKHEADERS dummy archive in disposable kernel checkout")


if __name__ == "__main__":
    main()
