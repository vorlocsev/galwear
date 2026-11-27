#!/usr/bin/env python3
"""Normalize IKHEADERS archive metadata in the pinned disposable kernel tree."""
import argparse
import hashlib
from pathlib import Path

PINNED_BLOB = "9ff449888d9cda491a39b0ffeba27c31d47a72b3"
OLD = "tar -Jcf $tarfile -C $cpio_dir/ . > /dev/null"
NEW = ('LC_ALL=C TZ=UTC XZ_OPT=-T1 XZ_DEFAULTS= tar --sort=name --format=gnu '
       '--mtime=@0 --owner=0 --group=0 --numeric-owner '
       '--mode=a=rX,u+w -Jcf "$tarfile" -C "$cpio_dir/" . > /dev/null')


def git_blob(data):
    return hashlib.sha1(("blob %d\0" % len(data)).encode("ascii") + data).hexdigest()


def normalize(data):
    if data.count(OLD.encode()) != 1:
        raise ValueError("Unexpected kheaders tar invocation")
    return data.replace(OLD.encode(), NEW.encode(), 1)


def apply(root):
    path = root / "kernel/gen_kheaders.sh"
    if path.is_symlink() or not path.is_file():
        raise ValueError("Missing or symlinked kheaders generator")
    data = path.read_bytes()
    if git_blob(data) != PINNED_BLOB:
        raise ValueError("Unexpected pinned kheaders generator blob")
    path.write_bytes(normalize(data))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path)
    args = parser.parse_args()
    apply(args.source)
    print("Normalized IKHEADERS archive metadata in disposable kernel checkout")


if __name__ == "__main__":
    main()
