#!/usr/bin/env python3
"""Experimental captured host loader/library tree; not a sandbox."""
import hashlib
from pathlib import Path
import stat
import subprocess
import re

from r800_android_userspace_preflight import read_regular
from r800_gps_host_elf import LIMIT, MAX_TOTAL, LOADER, NAME, TOOLS
from r800_gps_donor_snapshot import pinned_directory

# The linker wrapper is addressed explicitly by clang. No PATH lookup.
WRAPPER = b'''#!/bin/sh
set -eu
D=${0%/*}
if [ -n "${LD_DEBUG_OUTPUT:-}" ]; then
    export LD_DEBUG_OUTPUT="$LD_DEBUG_OUTPUT.linker"
fi
exec "$D/loader" --inhibit-cache --glibc-hwcaps-mask "" --library-path "$D/lib" "$D/../tools/ld.lld" "$@"
'''


def plan(report):
    if (report.get("status") != "HOST_STATIC_CANDIDATES_ONLY"
            or report.get("problems") != []):
        raise ValueError("Host closure requires review")
    objects, bindings = report["objects"], report["bindings"]
    if LOADER not in bindings:
        raise ValueError("Host loader not inventoried")
    loader = objects[bindings[LOADER]]
    if loader["interpreter"] is not None:
        raise ValueError("Host loader has an interpreter")
    for tool in TOOLS:
        if objects[bindings[tool]]["interpreter"] != LOADER:
            raise ValueError("Expected dynamically linked host tool: " + tool)
    result = {"loader": bindings[LOADER]}
    for name in sorted({n for obj in objects.values() for n in obj["needed"]}):
        if not NAME.fullmatch(name) or name in (".", "..") or name not in bindings:
            raise ValueError("Invalid host library binding")
        result["lib/" + name] = bindings[name]
    return result


def reject_preload():
    preload = Path("/etc/ld.so.preload")
    if preload.exists() or preload.is_symlink():
        raise ValueError("System-wide loader preload requires review")


def check_listing(text, staging, report, tool):
    """Reject unexpected paths from glibc --list (not an execution trace)."""
    base = Path(staging) / "host"
    expected = plan(report)
    objects, bindings = report["objects"], report["bindings"]
    pending = [bindings[tool], bindings[LOADER]]
    seen, names = set(), set()
    while pending:
        source = pending.pop()
        if source in seen:
            continue
        seen.add(source)
        for name in objects[source]["needed"]:
            names.add(name)
            pending.append(bindings[name])
    allowed = {str(base / "lib" / n): n for n in names}
    loader_path = str(base / "loader")
    listed = set()
    loader_seen = False
    for line in text.splitlines():
        match = re.fullmatch(r"\s*(.*?)\s+\(0x[0-9a-fA-F]+\)\s*", line)
        if not match:
            raise ValueError("Unexpected host loader listing")
        entry = match.group(1).strip()
        if entry == "linux-vdso.so.1":
            continue
        label, sep, path = entry.partition(" => ")
        path = path if sep else label
        if path == loader_path:
            if loader_seen:
                raise ValueError("Duplicate captured loader listing")
            loader_seen = True
            # The loader can also satisfy its own DT_NEEDED alias.
            listed.update(n for n in names if expected["lib/" + n] == bindings[LOADER])
        elif path in allowed and (not sep or label == allowed[path]):
            name = allowed[path]
            if name in listed:
                raise ValueError("Duplicate host library listing")
            listed.add(name)
        else:
            raise ValueError("Host dependency escaped captured library set: " + entry)
    if listed != names or not loader_seen:
        raise ValueError("Incomplete captured loader listing")


def check_loader(staging, report):
    reject_preload()
    staging = Path(staging)
    base = staging / "host"
    for tool in TOOLS:
        result = subprocess.run(
            [str(base / "loader"), "--inhibit-cache", "--glibc-hwcaps-mask", "",
             "--library-path", str(base / "lib"), "--list", str(staging / "tools" / tool)],
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "TZ": "UTC"},
            capture_output=True, text=True, timeout=30, check=False)
        if result.returncode or result.stderr:
            raise ValueError("Captured host loader review failed: " + tool)
        check_listing(result.stdout, staging, report, tool)


def snapshot(staging, report, *, create=False):
    """Build and recheck bounded copies from the audited closure."""
    paths = plan(report)
    root = Path(staging) / "host"
    if create:
        root.mkdir(mode=0o700)
        (root / "lib").mkdir(mode=0o700)
    total = 0
    with pinned_directory(root) as (base, _):
        with pinned_directory(base / "lib") as (libs, _):
            for name, source in paths.items():
                target = base / name if name == "loader" else libs / name[4:]
                expected = report["objects"][source]
                raw = read_regular(Path(source), LIMIT)
                total += len(raw)
                if total > MAX_TOTAL:
                    raise ValueError("Host snapshot byte budget exceeded")
                if len(raw) != expected["bytes"] or hashlib.sha256(raw).hexdigest() != expected["sha256"]:
                    raise ValueError("Host provider changed: " + name)
                mode = 0o500 if name == "loader" else 0o400
                if create:
                    with target.open("xb") as stream:
                        stream.write(raw)
                    target.chmod(mode)
                info = target.lstat()
                if (stat.S_IMODE(info.st_mode) != mode or info.st_nlink != 1
                        or hashlib.sha256(read_regular(target, LIMIT)).hexdigest() != expected["sha256"]):
                    raise ValueError("Host snapshot changed: " + name)
            wrapper = base / "ld.lld"
            if create:
                with wrapper.open("xb") as stream:
                    stream.write(WRAPPER)
                wrapper.chmod(0o500)
            if (stat.S_IMODE(wrapper.lstat().st_mode) != 0o500
                    or wrapper.lstat().st_nlink != 1
                    or read_regular(wrapper, 4096) != WRAPPER):
                raise ValueError("Host linker wrapper changed")
            if {p.name for p in base.iterdir()} != {"loader", "lib", "ld.lld"}:
                raise ValueError("Unexpected host snapshot entries")
            if {p.name for p in libs.iterdir()} != {p[4:] for p in paths if p.startswith("lib/")}:
                raise ValueError("Unexpected host library entries")
    reject_preload()
    return {"mode": "captured-loader-experimental", "providers": paths,
            "wrapper_sha256": hashlib.sha256(WRAPPER).hexdigest(),
            "host_isolated": False, "runtime_verified": False}
