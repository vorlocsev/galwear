#!/usr/bin/env python3
"""Convert Android sparse v1 images to bounded raw files; no mounting or flashing."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import struct
import tempfile
import zlib

MAGIC = 0xED26FF3A
RAW, FILL, SKIP, CRC = 0xCAC1, 0xCAC2, 0xCAC3, 0xCAC4
MAX_BYTES = 8 * 1024**3
BUFFER = 1024*1024


def exact(f, n):
    b = f.read(n)
    if len(b) != n:
        raise ValueError("Truncated sparse image")
    return b


def convert(source, output):
    source, output = Path(source).absolute(), Path(output).absolute()
    info = source.lstat()
    if not stat.S_ISREG(info.st_mode) or not 28 <= info.st_size <= MAX_BYTES:
        raise ValueError("Expected bounded regular sparse input")
    if output.exists() or output.is_symlink():
        raise ValueError("Output already exists")
    with tempfile.TemporaryDirectory(dir=output.parent) as tmp:
        candidate = Path(tmp) / "raw"
        with source.open("rb") as f, candidate.open("xb") as out:
            magic, major, minor, fh, ch, block, blocks, chunks, checksum = struct.unpack("<I4H4I", exact(f, 28))
            if (magic != MAGIC or major != 1 or minor != 0 or
                not 28 <= fh <= 4096 or not 12 <= ch <= 4096 or
                not 4 <= block <= BUFFER or block % 4 or
                not 1 <= blocks <= MAX_BYTES//block or
                not 1 <= chunks <= min(1000000, info.st_size//ch)):
                raise ValueError("Invalid sparse header")
            exact(f, fh-28)
            written = 0
            crc = 0
            digest = hashlib.sha256()
            counts = {"raw":0, "fill":0, "skip":0, "crc":0}
            def consume(b, hole=False):
                nonlocal crc, written
                if hole:
                    out.seek(len(b), os.SEEK_CUR)
                else:
                    out.write(b)
                crc = zlib.crc32(b, crc)
                digest.update(b)
                written += len(b)
            for _ in range(chunks):
                typ, reserved, nblocks, total = struct.unpack("<2H2I", exact(f, 12))
                exact(f, ch-12)
                n = nblocks * block
                if written + n > blocks * block:
                    raise ValueError("Sparse output exceeds declared geometry")
                if typ == CRC:
                    if nblocks or total != ch+4 or struct.unpack("<I", exact(f,4))[0] != crc:
                        raise ValueError("Sparse CRC chunk mismatch")
                    counts["crc"] += 1
                    continue
                if not nblocks:
                    raise ValueError("Empty sparse data chunk")
                if typ == RAW:
                    if total != ch+n:
                        raise ValueError("Invalid RAW chunk size")
                    counts["raw"] += 1
                    while n:
                        b = exact(f, min(n,BUFFER))
                        consume(b)
                        n -= len(b)
                elif typ in (FILL,SKIP):
                    if total != ch+(4 if typ==FILL else 0):
                        raise ValueError("Invalid FILL/SKIP chunk size")
                    pattern = exact(f,4) if typ==FILL else bytes(4)
                    counts["fill" if typ==FILL else "skip"] += 1
                    repeated = pattern*(BUFFER//4)
                    while n:
                        b = repeated[:min(n,BUFFER)]
                        consume(b, typ==SKIP)
                        n -= len(b)
                else:
                    raise ValueError("Unsupported sparse chunk type")
            if written != blocks*block or f.read(1):
                raise ValueError("Sparse geometry or trailing bytes mismatch")
            if checksum and checksum != crc:
                raise ValueError("Sparse header checksum mismatch")
            after = os.fstat(f.fileno())
            if (after.st_size, after.st_mtime_ns) != (info.st_size, info.st_mtime_ns):
                raise ValueError("Sparse input changed")
            out.truncate(written)
        os.link(candidate, output)
    return {"status":"RAW_DONOR_CONVERTED_ONLY", "bytes":written, "sha256":digest.hexdigest(),
            "crc32":format(crc,"08x"), "chunks":counts, "safe_to_flash":False}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--source",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True)
    a = p.parse_args()
    print(json.dumps(convert(a.source,a.output),sort_keys=True))


if __name__ == "__main__":
    main()
