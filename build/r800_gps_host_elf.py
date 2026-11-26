#!/usr/bin/env python3
"""Conservative Linux x86-64 host dependency inventory; never run target tools."""
import argparse
from collections import deque
import hashlib
import json
from pathlib import Path
import re
import struct

from r800_android_userspace_preflight import read_regular

LIMIT = 256 * 1024**2
MAX_TOTAL = 1024 * 1024**2
MAX_OBJECTS = 128
DEFAULT_DIRS = ("/lib/x86_64-linux-gnu", "/usr/lib/x86_64-linux-gnu",
                "/lib64", "/usr/lib64", "/lib", "/usr/lib")
TOOLS = ("clang", "ld.lld", "llvm-readelf")
NAME = re.compile(r"[A-Za-z0-9_.+-]+")
LOADER = "/lib64/ld-linux-x86-64.so.2"


def inspect(raw):
    if len(raw) < 64 or raw[:7] != b"\x7fELF\x02\x01\x01":
        raise ValueError("Expected little-endian ELF64 host tool")
    if struct.unpack_from("<HH", raw, 16) not in ((2, 62), (3, 62)):
        raise ValueError("Expected x86-64 ET_EXEC or ET_DYN")
    phoff = struct.unpack_from("<Q", raw, 32)[0]
    entry, count = struct.unpack_from("<HH", raw, 54)
    if entry != 56 or not 1 <= count <= 128 or phoff + count * entry > len(raw):
        raise ValueError("Invalid host program headers")
    loads, dynamic, interp = [], None, None
    for i in range(count):
        typ, flags, off, va, _, fs, ms, align = struct.unpack_from("<IIQQQQQQ", raw, phoff + i * entry)
        if typ in (1, 2, 3) and (fs > ms or off + fs > len(raw) or va + ms > 2**64):
            raise ValueError("Invalid host segment bounds")
        if typ == 1:
            if align > 1 and (align & (align - 1) or va % align != off % align):
                raise ValueError("Invalid host PT_LOAD alignment")
            if ms:
                if any(va < b and a < va + ms for a, b, _, _ in loads):
                    raise ValueError("Overlapping host PT_LOAD")
                loads.append((va, va + ms, off, fs))
        elif typ == 2:
            if dynamic is not None:
                raise ValueError("Duplicate host PT_DYNAMIC")
            dynamic = (off, va, fs)
        elif typ == 3:
            if interp is not None or not 2 <= fs <= 256:
                raise ValueError("Invalid host PT_INTERP")
            val = raw[off:off+fs]
            if not val.endswith(b"\0") or b"\0" in val[:-1]:
                raise ValueError("Invalid host interpreter string")
            interp = val[:-1].decode("ascii")
            if interp != LOADER:
                raise ValueError("Unsupported host interpreter")
    if not loads:
        raise ValueError("Missing host PT_LOAD")

    def mapping(va, size):
        if not 0 < size <= 2**64 - va:
            raise ValueError("Invalid host virtual range")
        hits = [off + va - a for a, b, off, fs in loads
                if a <= va and va + size <= a + fs]
        if len(hits) != 1:
            raise ValueError("Host data not uniquely file-backed")
        return hits[0]

    needed = []
    if dynamic is not None:
        off, va, size = dynamic
        if size % 16 or not 1 <= size // 16 <= 8192 or mapping(va, size) != off:
            raise ValueError("Invalid host dynamic table")
        tags = {}
        for pos in range(off, off + size, 16):
            tag, value = struct.unpack_from("<qQ", raw, pos)
            if tag == 0:
                break
            tags.setdefault(tag, []).append(value)
        else:
            raise ValueError("Missing host DT_NULL")
        if any(t in tags for t in (15, 29, 0x6ffffefb, 0x6ffffefc, 0x7ffffffd, 0x7fffffff)):
            raise ValueError("Host custom search path or loader extension requires review")
        if 1 in tags:
            if len(tags.get(5, [])) != 1 or len(tags.get(10, [])) != 1:
                raise ValueError("Missing host string table")
            size = tags[10][0]
            if size > 16 * 1024**2:
                raise ValueError("Host string table exceeds budget")
            start = mapping(tags[5][0], size)
            strings = raw[start:start+size]
            for index in tags[1]:
                end = strings.find(b"\0", index)
                if end < 0 or end - index > 255:
                    raise ValueError("Invalid host dependency name")
                name = strings[index:end].decode("ascii")
                if not NAME.fullmatch(name) or name in (".", ".."):
                    raise ValueError("Unsafe host dependency name")
                if name not in needed:
                    needed.append(name)
    return {"needed": needed, "interpreter": interp}


def audit(tools, *, directories=DEFAULT_DIRS, loader=LOADER):
    """Inventory explicit directory candidates, not glibc cache/search order."""
    dirs = tuple(Path(p) for p in directories)
    if len(dirs) > 16 or any(not p.is_absolute() for p in dirs):
        raise ValueError("Expected bounded absolute host library directories")
    queue = deque((str(name), Path(path)) for name, path in sorted(tools.items()))
    objects, bindings, problems = {}, {}, []
    total = 0
    while queue:
        label, path = queue.popleft()
        try:
            resolved = path.resolve(strict=True)
            key = str(resolved)
            if label in bindings and bindings[label] != key:
                raise ValueError("Conflicting host provider identity")
            bindings[label] = key
            if key in objects:
                continue
            if len(objects) >= MAX_OBJECTS:
                raise ValueError("Host object budget exceeded")
            raw = read_regular(resolved, LIMIT)
            total += len(raw)
            if total > MAX_TOTAL:
                raise ValueError("Host byte budget exceeded")
            info = inspect(raw)
            objects[key] = {"sha256": hashlib.sha256(raw).hexdigest(),
                            "bytes": len(raw), **info}
            if info["interpreter"]:
                queue.append((LOADER, Path(loader)))
            for name in info["needed"]:
                candidates = {}
                for directory in dirs:
                    try:
                        actual = (directory / name).resolve(strict=True)
                    except FileNotFoundError:
                        continue
                    candidates[str(actual)] = actual
                if len(candidates) != 1:
                    problems.append({"object": key, "needed": name,
                                     "reason": "MISSING" if not candidates else "AMBIGUOUS"})
                    continue
                queue.append((name, next(iter(candidates.values()))))
        except (OSError, ValueError, RuntimeError) as exc:
            problems.append({"object": str(path), "reason": str(exc)})
    return {"status": "HOST_STATIC_CANDIDATES_ONLY" if not problems else "HOST_REVIEW_REQUIRED",
            "objects": objects, "bindings": bindings, "problems": problems,
            "loader_search_verified": False, "runtime_verified": False,
            "host_isolated": False, "safe_to_flash": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tool-dir", required=True, type=Path)
    parser.add_argument("--libdir", action="append")
    args = parser.parse_args()
    try:
        report = audit({name: args.tool_dir / name for name in TOOLS},
                       directories=args.libdir or DEFAULT_DIRS)
    except (OSError, ValueError) as exc:
        report = {"status": "HOST_REVIEW_REQUIRED", "problems": [str(exc)],
                  "safe_to_flash": False}
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["status"] == "HOST_STATIC_CANDIDATES_ONLY" else 2


if __name__ == "__main__":
    raise SystemExit(main())
