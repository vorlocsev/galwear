#!/usr/bin/env python3
"""Bounded raw/sparse super extraction for explicit Android logical partitions.

No mounts, guest execution, slot guessing, AVB or hardware claims.
Sparse format v1.0, RAW/FILL/DONT_CARE/CRC32 only; unknown variants refused.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct
import tempfile
import zlib

from r800_super_inventory import MAX_IMAGE, inventory, require
from r800_graphics_donor_binding import checkout_sha

CHUNK = 1024*1024
MAX_CHUNKS = 1000000
SPARSE_MAGIC = b"\x3a\xff\x26\xed"
ALLOWED = re.compile(r"(?:system|system_ext|vendor|product|odm)(?:_[ab])?")


def identity(st):
    return (st.st_dev, st.st_ino, st.st_mode, st.st_size, st.st_mtime_ns, st.st_ctime_ns)


def normalize(image, raw, expected):
    """Private raw snapshot; hash exact input bytes and expanded bytes."""
    require(re.fullmatch(r"[0-9a-f]{64}", expected), "Expected super SHA-256")
    image, raw = Path(image), Path(raw)
    before = image.lstat()
    require(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= MAX_IMAGE,
            "Expected bounded regular super file")
    source_hash, raw_hash = hashlib.sha256(), hashlib.sha256()
    written, consumed, crc = 0, 0, 0
    fd = os.open(image, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as src:
        require(identity(os.fstat(src.fileno())) == identity(before), "Super input changed")
        def read(n):
            nonlocal consumed
            require(0 <= n <= CHUNK and consumed+n <= before.st_size, "Truncated super input")
            data = src.read(n)
            require(len(data) == n, "Truncated super input")
            consumed += n
            source_hash.update(data)
            return data
        first = read(4)
        with raw.open("xb") as dst:
            def emit(data):
                nonlocal written, crc
                require(written+len(data) <= MAX_IMAGE, "Raw super expansion budget exceeded")
                dst.write(data)
                written += len(data)
                raw_hash.update(data)
                crc = zlib.crc32(data, crc)
            def repeat(pattern, length):
                while length:
                    n = min(CHUNK, length)
                    emit((pattern*(n//len(pattern)+1))[:n])
                    length -= n
            if first == SPARSE_MAGIC:
                major, minor, fh, ch, block, blocks, chunks, image_crc = struct.unpack("<4H4I", read(24))
                require((major, minor, fh, ch, block) == (1, 0, 28, 12, 4096),
                        "Unsupported sparse header")
                expanded = blocks*block
                require(0 < expanded <= MAX_IMAGE and 0 < chunks <= MAX_CHUNKS,
                        "Sparse size or chunk count outside budget")
                for _ in range(chunks):
                    kind, reserved, count, total = struct.unpack("<HHII", read(12))
                    length = count*block
                    require(reserved == 0 and written+length <= expanded, "Invalid sparse chunk bounds")
                    if kind == 0xCAC1:
                        require(count > 0 and total == 12+length, "Invalid sparse RAW chunk")
                        while length:
                            n = min(CHUNK, length)
                            emit(read(n))
                            length -= n
                    elif kind == 0xCAC2:
                        require(count > 0 and total == 16, "Invalid sparse FILL chunk")
                        repeat(read(4), length)
                    elif kind == 0xCAC3:
                        require(count > 0 and total == 12, "Invalid sparse DONT_CARE chunk")
                        repeat(b"\0", length)
                    elif kind == 0xCAC4:
                        require(count == 0 and total == 16, "Invalid sparse CRC32 chunk")
                        require(struct.unpack("<I", read(4))[0] == crc, "Sparse CRC32 mismatch")
                    else:
                        raise ValueError("Unsupported sparse chunk type")
                require(written == expanded, "Sparse expanded size mismatch")
                require(not image_crc or crc == image_crc, "Sparse image CRC32 mismatch")
                fmt = "android_sparse_v1"
            else:
                emit(first)
                while consumed < before.st_size:
                    emit(read(min(CHUNK, before.st_size-consumed)))
                fmt = "raw"
            require(consumed == before.st_size, "Trailing sparse input bytes")
            require(source_hash.hexdigest() == expected, "Super input SHA-256 mismatch")
            require(identity(os.fstat(src.fileno())) == identity(before) and
                    identity(image.lstat()) == identity(before), "Super input changed")
    raw.chmod(0o400)
    return {"format": fmt, "source_sha256": expected, "source_bytes": consumed,
            "raw_sha256": raw_hash.hexdigest(), "raw_bytes": written}


def extract(image, expected, slot, names, output, source_sha):
    checkout_sha(source_sha)
    require(bool(names) and len(names) <= 10 and len(set(names)) == len(names) and
            all(ALLOWED.fullmatch(n) for n in names), "Explicit unique allowed partition names required")
    output = Path(output).absolute()
    require(not output.exists() and not output.is_symlink(), "Fresh output directory required")
    with tempfile.TemporaryDirectory(prefix="r800-super-", dir=output.parent) as temp:
        scratch = Path(temp)
        raw = scratch / "super.raw"
        origin = normalize(image, raw, expected)
        metadata = inventory(raw, origin["raw_sha256"], slot, source_sha)
        selected = []
        for n in names:
            part = metadata["partitions"].get(n)
            require(part and part["bytes"] > 0 and not part["disabled"],
                    "Absent, empty or disabled logical partition: " + n)
            selected.append((n, part))
        require(sum(p["bytes"] for _, p in selected) <= MAX_IMAGE, "Partition output budget exceeded")
        stage = scratch / "partitions"
        stage.mkdir()
        files = {}
        with raw.open("rb") as src:
            before = identity(os.fstat(src.fileno()))
            for n, part in selected:
                h = hashlib.sha256()
                count = 0
                dest = stage / (n+".img")
                with dest.open("xb") as dst:
                    for extent in part["extents"]:
                        remaining = extent["bytes"]
                        if extent["type"] == "linear":
                            src.seek(extent["offset"])
                        while remaining:
                            length = min(CHUNK, remaining)
                            data = src.read(length) if extent["type"] == "linear" else bytes(length)
                            require(len(data) == length, "Truncated logical extent")
                            dst.write(data)
                            h.update(data)
                            count += length
                            remaining -= length
                require(count == part["bytes"], "Logical partition size mismatch")
                dest.chmod(0o400)
                files[n] = {"file": dest.name, "bytes": count, "sha256": h.hexdigest()}
            require(identity(os.fstat(src.fileno())) == before, "Private raw super changed")
        checkout_sha(source_sha)
        report = {"schema": "galwear-r800-super-extraction-v1",
                  "status": "SUPER_SELECTED_PARTITIONS_EXTRACTED_ONLY",
                  "source_sha": source_sha, "input": origin, "metadata_slot": slot,
                  "metadata_sha256": metadata["metadata_sha256"],
                  "partitions": files, "all_slots_verified": False,
                  "filesystem_contents_verified": False, "avb_verified": False,
                  "wear_os_runtime_verified": False, "hardware_tested": False,
                  "safe_to_flash": False}
        (stage/"super-extraction.json").write_text(json.dumps(report, indent=2, sort_keys=True)+"\n")
        require(not output.exists() and not output.is_symlink(), "Output appeared during extraction")
        os.rename(stage, output)
    return report


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--image", type=Path, required=True)
    p.add_argument("--sha256", required=True)
    p.add_argument("--slot", type=int, required=True)
    p.add_argument("--partition", action="append", required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--source-sha", required=True)
    a = p.parse_args()
    result = extract(a.image, a.sha256, a.slot, a.partition, a.output, a.source_sha)
    print(result["status"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
