#!/usr/bin/env python3
"""Bounded Linux-host GPS donor snapshots; never execute donor bytes."""
import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path

from r800_android_userspace_preflight import read_regular

DONORS = ("libc.so.6", "libdl.so.2", "libpthread.so.0", "ld-linux.so.3")
LIMIT = 64 * 1024**2


def identity(info):
    return [info.st_dev, info.st_ino]


@contextmanager
def pinned_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        expected = identity(os.fstat(fd))
        anchor = Path("/proc/self/fd") / str(fd)
        if identity(path.lstat()) != expected:
            raise ValueError("Donor directory changed before reading")
        yield anchor, expected
        if identity(path.lstat()) != expected:
            raise ValueError("Donor directory changed while reading")
    finally:
        os.close(fd)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def create(source, dest):
    with pinned_directory(source) as (root, source_id):
        with pinned_directory(dest) as (snapshot, dest_id):
            hashes = {}
            for name in DONORS:
                data = read_regular(root / name, LIMIT)
                with (snapshot / name).open("xb") as stream:
                    stream.write(data)
                hashes[name] = digest(data)
            return {"source_id": source_id, "snapshot_id": dest_id, "sha256": hashes}


def verify(source, dest, manifest):
    if set(manifest["sha256"]) != set(DONORS):
        raise ValueError("Invalid donor manifest")
    with pinned_directory(source) as (root, source_id):
        with pinned_directory(dest) as (snapshot, dest_id):
            if source_id != manifest["source_id"] or dest_id != manifest["snapshot_id"]:
                raise ValueError("Donor directory identity changed")
            for name in DONORS:
                expected = manifest["sha256"][name]
                if (digest(read_regular(root / name, LIMIT)) != expected
                        or digest(read_regular(snapshot / name, LIMIT)) != expected):
                    raise ValueError("Donor bytes changed: " + name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("create", "verify"))
    parser.add_argument("source", type=Path)
    parser.add_argument("snapshot", type=Path)
    parser.add_argument("manifest", type=Path)
    args = parser.parse_args()
    try:
        if args.mode == "create":
            manifest = create(args.source, args.snapshot)
            with args.manifest.open("x", encoding="utf-8") as stream:
                json.dump(manifest, stream, sort_keys=True)
        else:
            manifest = json.loads(read_regular(args.manifest, 4096))
            verify(args.source, args.snapshot, manifest)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        parser.exit(2, "Donor snapshot rejected: " + str(exc) + "\n")


if __name__ == "__main__":
    main()
