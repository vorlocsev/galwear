#!/usr/bin/env python3
"""Review glibc loader diagnostics for captured NDK tools; not a sandbox."""
import re
from pathlib import Path

from r800_android_userspace_preflight import read_regular
from r800_gps_host_snapshot import plan
from r800_gps_donor_snapshot import DONORS

MAX_LOG = 4 * 1024**2
MAX_LOGS = 32
PID = re.compile(r"\s*([0-9]+):\s*(.*)")
MAP = re.compile(r"file=(.+) \[(\d+)\];\s+generating link map")
LOG_NAME = re.compile(r"(donor-[A-Za-z0-9_.+-]+|compile(?:\.linker)?|result)\.([0-9]+)")


def parse_log(raw, staging, report, *, tool, shell=False):
    """Match successful link maps and init/fini paths, not failed search attempts."""
    staging = Path(staging)
    host = staging / "host"
    program = "/bin/sh" if shell else str(staging / "tools" / tool)
    paths = plan(report)
    captured = {str(host / p): p for p in paths}
    originals = set(paths.values())
    observed = set()
    started = transferred = finished = False
    last_try = None
    pid = None

    def observe(path):
        if path == program or not path:
            return
        if not shell:
            if path not in captured:
                raise ValueError("Host library escaped captured set: " + path)
            observed.add(captured[path])
        else:
            if not path.startswith("/"):
                raise ValueError("Unresolved shell library path")
            resolved = str(Path(path).resolve(strict=True))
            if resolved not in originals:
                raise ValueError("Wrapper shell library not in audited host closure: " + path)
            observed.add(resolved)

    for line in raw.decode("utf-8", errors="strict").splitlines():
        match = PID.fullmatch(line)
        if not match:
            raise ValueError("Malformed host loader diagnostic")
        if pid is None:
            pid = match.group(1)
        elif pid != match.group(1):
            raise ValueError("Mixed host loader process IDs")
        body = match.group(2).strip()
        if body.startswith("trying file="):
            last_try = body[len("trying file="):]
        elif body.startswith("find library="):
            last_try = None
        elif body.startswith("file=") and "generating link map" in body:
            mapping = MAP.fullmatch(body)
            if not mapping or mapping.group(2) != "0":
                raise ValueError("Unsupported host link-map diagnostic")
            name = mapping.group(1)
            if name.startswith("/"):
                observe(name)
            elif last_try is not None and Path(last_try).name == name:
                observe(last_try)
            else:
                raise ValueError("Host link map lacks a resolved path: " + name)
            last_try = None
        elif body.startswith("calling init:"):
            observe(body[len("calling init:"):].strip())
        elif body.startswith("calling fini:"):
            path = body[len("calling fini:"):].strip()
            if not path.endswith(" [0]") and path != "[0]":
                raise ValueError("Unsupported host fini diagnostic")
            path = "" if path == "[0]" else path[:-4]
            observe(path)
            finished = True
        elif body.startswith("initialize program:"):
            if started or body[len("initialize program:"):].strip() != program:
                raise ValueError("Unexpected host trace program")
            started = True
        elif body.startswith("transferring control:"):
            if not started or transferred or body[len("transferring control:"):].strip() != program:
                raise ValueError("Unexpected host trace transfer")
            transferred = True
    if not started or not transferred or (not shell and not finished):
        raise ValueError("Incomplete host loader diagnostics")
    if not shell and "loader" not in observed:
        raise ValueError("Captured loader missing from diagnostics")
    return sorted(observed)


def summarize(staging, report):
    staging = Path(staging)
    root = staging / "host-trace"
    if root.is_symlink() or not root.is_dir():
        raise ValueError("Missing real host trace directory")
    # Each invocation uses a fresh prefix; the linker wrapper switches prefix
    # after its own shell startup, so the two exec images are not conflated.
    expected = {"donor-" + name: "llvm-readelf" for name in DONORS}
    expected.update({"compile": "clang", "compile.linker": "ld.lld", "result": "llvm-readelf"})
    records = {}
    shell_count = 0
    shell_libraries = []
    items = list(root.iterdir())
    if not 1 <= len(items) <= MAX_LOGS:
        raise ValueError("Invalid host trace file count")
    for path in sorted(items):
        match = LOG_NAME.fullmatch(path.name)
        if not match or match.group(1) not in expected:
            raise ValueError("Unexpected host trace file: " + path.name)
        raw = read_regular(path, MAX_LOG)
        role, pid = match.groups()
        if any(m.group(1) != pid for line in raw.decode("utf-8").splitlines()
               if (m := PID.fullmatch(line))):
            raise ValueError("Host trace filename/process mismatch")
        if role == "compile" and b"initialize program: /bin/sh" in raw:
            shell_count += 1
            if shell_count != 1:
                raise ValueError("Unexpected number of linker wrapper shells")
            shell_libraries = parse_log(raw, staging, report, tool="ld.lld", shell=True)
            continue
        if role in records:
            raise ValueError("Duplicate host tool trace: " + role)
        records[role] = parse_log(raw, staging, report, tool=expected[role])
    if set(records) != set(expected) or shell_count != 1:
        raise ValueError("Missing captured host tool execution diagnostics")
    return {"status": "HOST_LOADER_DIAGNOSTICS_MATCH",
            "method": "glibc-LD_DEBUG-files-libs", "observed": records,
            "wrapper_shell_libraries": shell_libraries,
            "host_isolated": False, "runtime_verified": False,
            "safe_to_flash": False}
