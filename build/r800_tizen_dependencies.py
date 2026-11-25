#!/usr/bin/env python3
"""Inventory Tizen ARM32 userspace dependencies from an offline, clean donor tree."""
from collections import deque
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import stat
import struct
from r800_android_linker_audit import inspect
from r800_android_userspace_preflight import read_regular

TARGETS = ("/usr/bin/lhd", "/usr/bin/gpsd", "/usr/bin/sensord",
           "/usr/bin/sensorctl", "/usr/bin/env", "/usr/bin/chown",
           "/usr/lib/libbrcm.so")
DIRS = ("/lib", "/usr/lib", "/usr/lib/sensor")
MAX_NODES = 256
MAX_FILE = 64*1024**2
MAX_TOTAL = 256*1024**2

def resolve_guest(root, guest):
    """Resolve guest absolute symlinks within donor root, never on host."""
    if not guest.startswith("/"):
        raise ValueError("Expected absolute guest path")
    parts = deque(PurePosixPath(guest).parts[1:])
    done = []
    links = 0
    while parts:
        part = parts.popleft()
        if part in ("", "."):
            continue
        if part == "..":
            if not done:
                raise ValueError("Guest link escapes root")
            done.pop()
            continue
        candidate = root.joinpath(*done, part)
        st = candidate.lstat()
        if stat.S_ISLNK(st.st_mode):
            links += 1
            if links > 40:
                raise ValueError("Guest symlink loop")
            target = candidate.readlink()
            if target.is_absolute():
                done.clear()
            parts.extendleft(reversed(target.parts[1:] if target.is_absolute() else target.parts))
        else:
            if parts and not stat.S_ISDIR(st.st_mode):
                raise ValueError("Guest parent is not a directory")
            done.append(part)
    path = root.joinpath(*done)
    relative = "/" + "/".join(done)
    if not relative.startswith(("/usr/bin/", "/bin/", "/usr/lib/", "/lib/")):
        raise ValueError("Guest executable/library outside allowed roots")
    return path, relative

def interpreter(raw):
    if len(raw) < 52 or raw[:7] != b"\x7fELF\x01\x01\x01":
        raise ValueError("Expected ARM32 ELF")
    phoff = struct.unpack_from("<I", raw, 28)[0]
    entry, count = struct.unpack_from("<HH", raw, 42)
    if entry != 32 or not 1 <= count <= 128 or phoff+entry*count > len(raw):
        raise ValueError("Invalid program headers")
    paths = []
    for i in range(count):
        typ, off, _, _, size, _, _, _ = struct.unpack_from("<8I", raw, phoff+i*entry)
        if typ == 3:
            if not 2 <= size <= 256 or off+size > len(raw):
                raise ValueError("Invalid PT_INTERP bounds")
            value = raw[off:off+size]
            if not value.endswith(b"\0") or b"\0" in value[:-1]:
                raise ValueError("Invalid PT_INTERP string")
            paths.append(value[:-1].decode("ascii"))
    if len(paths)>1:
        raise ValueError("Duplicate PT_INTERP")
    if paths and paths[0] != "/lib/ld-linux.so.3":
        raise ValueError("Unexpected Tizen ARM soft-float interpreter")
    return paths[0] if paths else None

def audit(root, targets=TARGETS):
    root = root.resolve(strict=True)
    queue = deque(targets)
    visited, files, edges, problems = set(), {}, [], []
    total = 0
    while queue:
        guest = queue.popleft()
        if guest in visited:
            continue
        if len(visited) >= MAX_NODES:
            raise ValueError("Tizen dependency count exceeds budget")
        visited.add(guest)
        try:
            path, canonical = resolve_guest(root, guest)
            if canonical in files:
                continue
            raw = read_regular(path, MAX_FILE)
            total += len(raw)
            if total > MAX_TOTAL:
                raise ValueError("Tizen dependency byte budget exceeded")
            info = inspect(raw)
            if info["abi"] != "arm":
                raise ValueError("Expected Tizen ARM32 ABI")
            interp = interpreter(raw)
            if info["custom_search_path"]:
                problems.append({"path":guest,"reason":"RPATH/RUNPATH requires review"})
            files[canonical] = {"bytes":len(raw), "sha256":hashlib.sha256(raw).hexdigest(),
                                "needed":info["needed"], "interpreter":interp,
                                "version_needs":info["version_needs"]}
            if interp:
                queue.append(interp)
                edges.append({"from":guest,"needed":interp,"provider":interp})
            for dep in info["needed"]:
                if not re.fullmatch(r"[A-Za-z0-9_.+-]+", dep) or dep in (".",".."):
                    raise ValueError("Unsafe dependency name")
                providers = {}
                for directory in DIRS:
                    candidate = directory+"/"+dep
                    try:
                        _, real = resolve_guest(root, candidate)
                        providers.setdefault(real, candidate)
                    except FileNotFoundError:
                        continue
                if len(providers)!=1:
                    problems.append({"path":guest,"needed":dep,
                                     "reason":"MISSING" if not providers else "AMBIGUOUS",
                                     "candidates":sorted(providers)})
                    continue
                provider = next(iter(providers.values()))
                edges.append({"from":guest,"needed":dep,"provider":provider})
                queue.append(provider)
        except (OSError, ValueError) as exc:
            problems.append({"path":guest,"reason":str(exc)})
    return {"status":"TIZEN_DEPENDENCY_REVIEW_REQUIRED" if problems else "TIZEN_STATIC_CLOSURE_ONLY",
            "files":files,"edges":edges,"problems":problems,
            "dlopen_plugins_verified":False,"symbol_resolution_verified":False,
            "permissions_verified":False,"runtime_verified":False,"safe_to_flash":False}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--root",type=Path,required=True)
    a=p.parse_args()
    report=audit(a.root)
    print(json.dumps(report,indent=2,sort_keys=True))
    return 2 if report["problems"] else 0

if __name__=="__main__":
    raise SystemExit(main())
