#!/usr/bin/env python3
"""Deterministic uncompressed USTAR for a verified Tizen ELF subset only."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import tarfile
import tempfile

from r800_android_userspace_preflight import read_regular
from r800_tizen_dependencies import MAX_FILE, MAX_TOTAL
from r800_verify_tizen_stage import (verify, guest_name, unique_keys, MANIFEST,
                                     MAX_MANIFEST, MAX_ENTRIES)

BLOCK = 512
RECORD = 10240
MAX_ARCHIVE = MAX_TOTAL + MAX_MANIFEST + (MAX_ENTRIES + 1) * 1024 + RECORD * 2


def manifest_bytes(report):
    return json.dumps(report, indent=2, sort_keys=True, allow_nan=False).encode("utf-8")


def header(name, size, mode):
    item = tarfile.TarInfo(name)
    item.size, item.mode = size, mode
    item.uid = item.gid = item.mtime = 0
    return item.tobuf(format=tarfile.USTAR_FORMAT, encoding="ascii", errors="strict")


def padding(size):
    return (-size) % BLOCK


def members(report):
    if not isinstance(report, dict):
        raise ValueError("Invalid archive manifest")
    files = report.get("files")
    if not isinstance(files, dict) or not 1 <= len(files) <= MAX_ENTRIES:
        raise ValueError("Invalid archive file count")
    for guest, row in sorted(files.items()):
        name = guest_name(guest)
        if (not isinstance(row, dict) or type(row.get("bytes")) is not int
                or not 0 < row["bytes"] <= MAX_FILE
                or row.get("mode") not in ("0o644", "0o755")):
            raise ValueError("Invalid archive member metadata")
        yield name, row


def bind_donors(report, donor_hashes):
    """Match the four exact linker inputs against verified guest library paths."""
    from r800_gps_donor_snapshot import DONORS
    if not isinstance(donor_hashes, dict) or set(donor_hashes) != set(DONORS):
        raise ValueError("Invalid archive donor hash set")
    files = report["files"]
    bound = {}
    for name in DONORS:
        paths = [p for p in ("/lib/" + name, "/usr/lib/" + name) if p in files]
        if not paths:
            raise ValueError("Archive donor missing: " + name)
        sources = {files[p]["source"] for p in paths}
        if len(sources) != 1:
            raise ValueError("Ambiguous archive donor: " + name)
        if any(files[p]["sha256"] != donor_hashes[name] for p in paths):
            raise ValueError("Archive donor digest mismatch: " + name)
        bound[name] = {"paths": paths, "source": next(iter(sources)),
                       "sha256": donor_hashes[name]}
    return bound


def verify_archive(path, *, expected=None, donor_hashes=None):
    """Check exact canonical bytes; never use tar extraction APIs."""
    raw = read_regular(Path(path), MAX_ARCHIVE)
    pos = 0

    def take(name, size, mode):
        nonlocal pos
        end = pos + BLOCK + size
        after = end + padding(size)
        if after > len(raw) or raw[pos:pos + BLOCK] != header(name, size, mode):
            raise ValueError("Noncanonical or missing archive member: " + name)
        if any(raw[end:after]):
            raise ValueError("Nonzero archive member padding")
        data = raw[pos + BLOCK:end]
        pos = after
        return data

    if len(raw) < BLOCK:
        raise ValueError("Truncated archive")
    try:
        first = tarfile.TarInfo.frombuf(raw[:BLOCK], "ascii", "strict")
    except tarfile.HeaderError as exc:
        raise ValueError("Invalid manifest header") from exc
    if not 0 < first.size <= MAX_MANIFEST:
        raise ValueError("Invalid archive manifest size")
    encoded = take(MANIFEST, first.size, 0o644)
    report = json.loads(encoded, object_pairs_hook=unique_keys)
    if manifest_bytes(report) != encoded:
        raise ValueError("Noncanonical archive manifest")
    if expected is not None and report != expected:
        raise ValueError("Archive manifest differs from trusted staging result")
    # Use only manifest-validated paths in a private scratch tree.
    # No archive-provided path, link, owner, or device metadata is applied.
    with tempfile.TemporaryDirectory() as tmp:
        tree = Path(tmp)
        (tree / MANIFEST).write_bytes(encoded)
        total = 0
        for name, row in members(report):
            size = row["bytes"]
            total += size
            if total > MAX_TOTAL:
                raise ValueError("Archive byte budget exceeded")
            mode = int(row["mode"], 8)
            data = take(name, size, mode)
            dest = tree / name
            dest.parent.mkdir(parents=True, exist_ok=True)
            with dest.open("xb") as out:
                out.write(data)
            dest.chmod(mode)
        end = pos + 2 * BLOCK
        expected_size = end + (-end) % RECORD
        if len(raw) != expected_size or any(raw[pos:]):
            raise ValueError("Unexpected archive trailer or additional members")
        result = verify(tree, expected=report)
    bound = bind_donors(report, donor_hashes) if donor_hashes is not None else None
    return {"status": "TIZEN_ELF_ARCHIVE_STATIC_ONLY",
            "donor_bindings": bound,
            "sha256": hashlib.sha256(raw).hexdigest(),
            "archive_bytes": len(raw), "file_count": result["file_count"],
            "manifest_matches_expected": expected is not None,
            "strict_4k_page_review": True, "runtime_verified": False,
            "safe_to_flash": False}


def pack(root, output):
    root, output = Path(root), Path(output).absolute()
    if output.resolve().is_relative_to(root.resolve(strict=True)):
        raise ValueError("Archive must be outside staging tree")
    if output.exists() or output.is_symlink():
        raise ValueError("Archive output already exists")
    report = json.loads(read_regular(root / MANIFEST, MAX_MANIFEST),
                        object_pairs_hook=unique_keys)
    verify(root, expected=report)
    encoded = manifest_bytes(report)
    if len(encoded) > MAX_MANIFEST:
        raise ValueError("Archive manifest too large")
    with tempfile.TemporaryDirectory(dir=output.parent) as tmp:
        candidate = Path(tmp) / "subset.tar"
        with candidate.open("xb") as out:
            def write(name, data, mode):
                out.write(header(name, len(data), mode))
                out.write(data)
                out.write(bytes(padding(len(data))))
            write(MANIFEST, encoded, 0o644)
            total = 0
            for name, row in members(report):
                data = read_regular(root / name, MAX_FILE)
                total += len(data)
                if total > MAX_TOTAL or len(data) != row["bytes"] or hashlib.sha256(data).hexdigest() != row["sha256"]:
                    raise ValueError("Staged ELF changed before packing")
                write(name, data, int(row["mode"], 8))
            out.write(bytes(2 * BLOCK))
            out.write(bytes((-out.tell()) % RECORD))
            out.flush()
            os.fsync(out.fileno())
        result = verify_archive(candidate, expected=report)
        # Recheck source tree before no-replace publication.
        verify(root, expected=report)
        os.link(candidate, output, follow_symlinks=False)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    create = sub.add_parser("pack")
    create.add_argument("--root", required=True, type=Path)
    create.add_argument("--output", required=True, type=Path)
    check = sub.add_parser("verify")
    check.add_argument("--archive", required=True, type=Path)
    check.add_argument("--donor-manifest", type=Path)
    args = parser.parse_args()
    try:
        if args.command == "pack":
            report = pack(args.root, args.output)
        else:
            hashes = None
            if args.donor_manifest is not None:
                hashes = json.loads(read_regular(args.donor_manifest, 4096),
                                    object_pairs_hook=unique_keys)["sha256"]
            report = verify_archive(args.archive, donor_hashes=hashes)
    except (OSError, ValueError, KeyError, TypeError, RecursionError, tarfile.TarError) as exc:
        report = {"status": "REVIEW_REQUIRED", "error": str(exc), "safe_to_flash": False}
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["status"] == "TIZEN_ELF_ARCHIVE_STATIC_ONLY" else 2


if __name__ == "__main__":
    raise SystemExit(main())
