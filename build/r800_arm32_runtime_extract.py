#!/usr/bin/env python3
"""Extract minimal ARM32 Bionic runtime from a hash-pinned Android system image.

No host mounts, no guest execution, no NDK link stubs, no signature claim.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

from r800_android_runtime_extract import unpack_system, extract_payload, MAX_APEX
from r800_extract_ext4 import snapshot_image, locate, command
from r800_vendor_inputs import image_info
from r800_android_userspace_preflight import read_regular
from r800_hal_dlopen_probe import (check, RUNTIME, LIMIT, runtime_dependencies,
                                   LINKER_SONAME, SYSTEM_RUNTIME_LIBS)

# Android 10/11 runtime APEX layout. liblog and libc++ are outside Runtime APEX.
APEX_PATHS = ("/apex/com.android.runtime.apex", "/system/apex/com.android.runtime.apex")
SYSTEM_LIB_PATHS = {name: ("/lib/" + name, "/system/lib/" + name)
                    for name in SYSTEM_RUNTIME_LIBS}
FILES = {"linker": "/bin/linker", "libc.so": "/lib/bionic/libc.so",
         "libdl.so": "/lib/bionic/libdl.so", "libm.so": "/lib/bionic/libm.so"}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def get_member(tool, image, paths, scratch, limit):
    found = []
    for path in paths:
        row = locate(tool, image, path, limit)
        if row is not None:
            found.append((path, row))
    if len(found) != 1:
        raise ValueError("Expected one regular member: " + ", ".join(paths))
    path, (inode, size) = found[0]
    dest = scratch/"member"
    try:
        command(tool, image, "dump <%d> member" % inode, cwd=scratch)
        raw = read_regular(dest, limit)
        if len(raw) != size:
            raise ValueError("Member size mismatch: " + path)
        return path, raw
    finally:
        dest.unlink(missing_ok=True)


def extract(system, expected, output):
    if not re.fullmatch(r"[0-9a-f]{64}", expected):
        raise ValueError("Expected pinned system SHA-256")
    system, output = system.absolute(), output.absolute()
    if output.exists() or output.is_symlink():
        raise ValueError("Fresh runtime output required")
    tool = shutil.which("debugfs")
    if not tool:
        raise ValueError("debugfs required")
    with tempfile.TemporaryDirectory(prefix="r800-arm32-runtime-", dir=output.parent) as tmp:
        scratch = Path(tmp)
        snapshot = scratch/"source.img"
        identity = snapshot_image(system, snapshot, expected)
        raw_system = unpack_system(snapshot, scratch)
        before = image_info(raw_system)
        packaged = [path for path in APEX_PATHS if locate(tool, raw_system, path, MAX_APEX) is not None]
        flat = [prefix for prefix in ("/apex/com.android.runtime", "/system/apex/com.android.runtime")
                if locate(tool, raw_system, prefix + "/bin/linker", LIMIT) is not None]
        if len(packaged) + len(flat) != 1:
            raise ValueError("Expected exactly one packaged or flattened ARM32 Runtime APEX")
        payload = None
        payload_before = None
        apex_bytes = None
        if packaged:
            source, apex_bytes = get_member(tool, raw_system, tuple(packaged), scratch, MAX_APEX)
            apex = scratch/"runtime.apex"
            apex.write_bytes(apex_bytes)
            payload = scratch/"runtime-payload.img"
            extract_payload(apex, payload)
            payload.chmod(0o400)
            payload_before = image_info(payload)
            layout = "PACKAGED_APEX"
        else:
            source = flat[0]
            layout = "FLATTENED_APEX"
        stage = scratch/"stage"
        stage.mkdir()
        rows = {}
        linker_soname = None
        for name in RUNTIME:
            if name in SYSTEM_RUNTIME_LIBS:
                guest, raw = get_member(tool, raw_system, SYSTEM_LIB_PATHS[name], scratch, LIMIT)
                origin = "system"
            else:
                filesystem = payload if payload is not None else raw_system
                member = FILES[name] if payload is not None else source + FILES[name]
                guest, raw = get_member(tool, filesystem, (member,), scratch, LIMIT)
                origin = "com.android.runtime"
            dest = stage/name
            dest.write_bytes(raw)
            checked, info = check(dest, library=name != "linker")
            if checked != raw:
                raise ValueError("Runtime member changed: " + name)
            if name == "linker":
                linker_soname = info["soname"]
            runtime_dependencies(name, info, linker_soname)
            dest.chmod(0o555 if name == "linker" else 0o444)
            rows[name] = {"sha256": sha(raw), "bytes": len(raw), "origin": origin,
                          "guest_path": guest, "needed": info["needed"], "soname": info["soname"]}
        if image_info(raw_system) != before or (payload is not None and image_info(payload) != payload_before):
            raise ValueError("Read-only extraction input changed")
        current = system.lstat()
        if (current.st_dev, current.st_ino, current.st_mode, current.st_size,
                current.st_mtime_ns, current.st_ctime_ns) != identity:
            raise ValueError("System donor changed")
        pins = {name: row["sha256"] for name, row in rows.items()}
        report = {"status": "ARM32_BIONIC_RUNTIME_EXTRACTED_STATIC_ONLY",
                  "system_sha256": expected, "raw_system_sha256": before["sha256"],
                  "apex_path": source, "apex_layout": layout,
                  "apex_sha256": sha(apex_bytes) if apex_bytes is not None else None,
                  "apex_payload_sha256": payload_before["sha256"] if payload_before else None, "files": rows,
                  "linker_soname": linker_soname,
                  "linker_provides_ld_android": linker_soname == LINKER_SONAME,
                  "runtime_authenticity_verified": False, "android_version_verified": False,
                  "apex_signature_verified": False, "runtime_stub_exclusion_proven": False,
                  "runtime_verified": False, "safe_to_flash": False}
        (stage/"runtime-manifest.json").write_text(json.dumps(pins, indent=2, sort_keys=True)+"\n")
        (stage/"runtime-extraction.json").write_text(json.dumps(report, indent=2, sort_keys=True)+"\n")
        os.rename(stage, output)
    return report


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--system-image", type=Path, required=True)
    p.add_argument("--sha256", required=True)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    print(json.dumps(extract(a.system_image, a.sha256, a.output), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
