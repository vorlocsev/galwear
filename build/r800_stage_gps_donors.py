#!/usr/bin/env python3
"""Stage resolved Tizen glibc files for offline GPS link/QEMU checks."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat

LIBS = ("libc.so.6", "libdl.so.2", "libpthread.so.0", "ld-linux.so.3")
LIMIT = 64 * 1024**2


def read_source(path):
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= LIMIT:
            raise ValueError("Expected bounded regular donor file")
        raw = stream.read(LIMIT + 1)
        after = os.fstat(stream.fileno())
        if len(raw) != before.st_size or (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise ValueError("Donor changed while reading")
        return raw


def stage(root, output, resolve, validate):
    root = Path(root).resolve(strict=True)
    output = Path(output)
    output = output.parent.resolve(strict=True) / output.name
    if not root.is_dir() or root == Path("/") or output == root or root in output.parents:
        raise ValueError("Use an isolated donor root and a new output outside it")
    if output.exists() or output.is_symlink():
        raise ValueError("Output already exists")
    items = {}
    for name in LIBS:
        candidates = []
        for directory in ("/lib", "/usr/lib"):
            try:
                path, canonical = resolve(root, directory + "/" + name)
                raw = read_source(path)
            except FileNotFoundError:
                continue
            info = validate(raw)
            if info["soname"] != name:
                raise ValueError("Unexpected SONAME: " + name)
            candidates.append((canonical, raw, hashlib.sha256(raw).hexdigest()))
        if not candidates:
            raise ValueError("Missing donor: " + name)
        if len({entry[2] for entry in candidates}) != 1:
            raise ValueError("Conflicting donor candidates: " + name)
        items[name] = candidates[0]
    report = {"status": "STAGED_STATIC_INPUTS_ONLY", "files": {
        name: {"guest_path": path, "sha256": digest, "size": len(raw)}
        for name, (path, raw, digest) in items.items()},
        "donor_authenticity_verified": False, "runtime_verified": False,
        "safe_to_flash": False}
    output.mkdir(mode=0o700)
    created = []
    try:
        for name, (_, raw, _) in items.items():
            path = output / name
            with path.open("xb") as stream:
                created.append(path)
                stream.write(raw)
        path = output / "manifest.json"
        with path.open("x", encoding="utf-8") as stream:
            created.append(path)
            json.dump(report, stream, indent=2, sort_keys=True)
            stream.write("\n")
    except Exception:
        for path in reversed(created):
            path.unlink()
        output.rmdir()
        raise
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    from r800_tizen_dependencies import resolve_guest
    from r800_gps_link_gate import elf
    try:
        report = stage(args.root, args.output, resolve_guest, elf)
    except (OSError, ValueError) as exc:
        print(json.dumps({"status": "REVIEW_REQUIRED", "problems": [str(exc)], "safe_to_flash": False}))
        return 2
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
