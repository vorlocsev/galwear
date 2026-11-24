#!/usr/bin/env python3
"""Compile selected pinned Mali R28P0 ioctl layouts against both Android ABIs."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

PIN = "50db73fc799f20a7120a8b5f653b16cc123d856f"
BASE = "drivers/gpu/arm/t72x/r28p0/"
# Linux asm-generic ioctl encoding: direction, number, byte size, declaration.
OPS = {
    "VERSION_CHECK": (3, 0, 4, "struct kbase_ioctl_version_check"),
    "SET_FLAGS": (1, 1, 4, "struct kbase_ioctl_set_flags"),
    "JOB_SUBMIT": (1, 2, 16, "struct kbase_ioctl_job_submit"),
    "GET_GPUPROPS": (1, 3, 16, "struct kbase_ioctl_get_gpuprops"),
    "MEM_ALLOC": (3, 5, 32, "union kbase_ioctl_mem_alloc"),
    "MEM_QUERY": (3, 6, 16, "union kbase_ioctl_mem_query"),
    "MEM_FREE": (1, 7, 8, "struct kbase_ioctl_mem_free"),
    "MEM_SYNC": (1, 15, 32, "struct kbase_ioctl_mem_sync"),
    "MEM_COMMIT": (1, 20, 16, "struct kbase_ioctl_mem_commit"),
    "MEM_IMPORT": (3, 22, 24, "union kbase_ioctl_mem_import"),
    "STREAM_CREATE": (1, 24, 32, "struct kbase_ioctl_stream_create"),
    "FENCE_VALIDATE": (1, 25, 4, "struct kbase_ioctl_fence_validate"),
}
OFFSETS = (
    ("struct kbase_ioctl_job_submit", "nr_atoms", 8),
    ("struct kbase_ioctl_job_submit", "stride", 12),
    ("struct kbase_ioctl_get_gpuprops", "size", 8),
    ("union kbase_ioctl_mem_alloc", "in.flags", 24),
    ("union kbase_ioctl_mem_import", "in.phandle", 8),
    ("union kbase_ioctl_mem_import", "in.type", 16),
    ("union kbase_ioctl_mem_import", "out.va_pages", 16),
    ("struct kbase_ioctl_mem_sync", "type", 24),
)


def command(direction, number, size):
    return (direction << 30) | (size << 16) | (0x80 << 8) | number


def source_unit():
    lines = ['#include <stddef.h>', '#include "mali_kbase_ioctl.h"',
             '_Static_assert(BASE_UK_VERSION_MAJOR == 11, "major");',
             '_Static_assert(BASE_UK_VERSION_MINOR == 13, "minor");',
             '_Static_assert(KBASE_IOCTL_TYPE == 0x80, "type");']
    for name, (direction, number, size, decl) in OPS.items():
        lines.append(f'_Static_assert(sizeof({decl}) == {size}, "{name} size");')
        lines.append(f'_Static_assert(KBASE_IOCTL_{name} == 0x{command(direction, number, size):08x}UL, "{name} command");')
    for decl, field, offset in OFFSETS:
        lines.append(f'_Static_assert(offsetof({decl}, {field}) == {offset}, "{field} offset");')
    return "\n".join(lines) + "\n"


def check_dispatch(core):
    core = re.sub(r"/\*.*?\*/|//[^\n]*", "", core, flags=re.S)
    for name in OPS:
        if not re.search(r"\bcase\s+KBASE_IOCTL_" + name + r"\s*:", core):
            raise ValueError("Missing dispatcher case " + name)
    for member in ("unlocked_ioctl", "compat_ioctl"):
        if not re.search(r"\." + member + r"\s*=\s*kbase_ioctl\s*,", core):
            raise ValueError("Unexpected ioctl entry " + member)
    for name in ("stream_create", "fence_validate"):
        match = re.search(r"static int kbase_api_" + name + r"\s*\([^)]*\)\s*\{(.*?)\n\}", core, re.S)
        if not match or not re.search(r"#if\s+defined\(CONFIG_SYNC\)\s*\|\|\s*defined\(CONFIG_SYNC_FILE\)", match.group(1)):
            raise ValueError("Unexpected fence configuration gate " + name)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--source", required=True, type=Path, help="Pinned git checkout or FETCH_HEAD repository")
    p.add_argument("--ndk", required=True, type=Path)
    p.add_argument("--scratch", required=True, type=Path)
    p.add_argument("--output", required=True, type=Path)
    a = p.parse_args()
    a.scratch.mkdir(parents=True, exist_ok=False)
    revision = subprocess.check_output(["git", "-C", str(a.source), "rev-parse", "FETCH_HEAD"], text=True).strip()
    if revision != PIN:
        raise ValueError("Incorrect pinned source revision")
    def extract(name):
        data = subprocess.check_output(["git", "-C", str(a.source), "show", PIN + ":" + BASE + name], timeout=60)
        if not 0 < len(data) <= 2 * 1024 * 1024:
            raise ValueError("Source size out of bounds")
        return data
    header = extract("mali_kbase_ioctl.h")
    core = extract("mali_kbase_core_linux.c")
    check_dispatch(core.decode("utf-8"))
    (a.scratch / "mali_kbase_ioctl.h").write_bytes(header)
    unit = a.scratch / "abi.c"
    unit.write_text(source_unit())
    bindir = a.ndk / "toolchains/llvm/prebuilt/linux-x86_64/bin"
    targets = ("armv7a-linux-androideabi28-clang", "aarch64-linux-android28-clang")
    for compiler in targets:
        subprocess.run([str(bindir / compiler), "-std=gnu11", "-DMALI_UNIT_TEST=0",
                        "-fsyntax-only", str(unit)], check=True, timeout=30)
    report = {
        "schema": "galwear-r800-mali-abi-v1",
        "status": "PINNED_HEADER_LAYOUT_COMPILED_BOTH_ABIS",
        "source_commit": PIN, "commit": os.getenv("GITHUB_SHA"),
        "run_id": os.getenv("GITHUB_RUN_ID"), "run_attempt": os.getenv("GITHUB_RUN_ATTEMPT"),
        "uk_version": "11.13", "targets": list(targets),
        "header_sha256": hashlib.sha256(header).hexdigest(),
        "dispatcher_sha256": hashlib.sha256(core).hexdigest(),
        "ioctls": {n: {"size": v[2], "command": f"0x{command(*v[:3]):08x}"} for n,v in OPS.items()},
        "donor_library_abi_verified": False, "runtime_ioctl_tested": False,
        "gpu_rendering_tested": False, "safe_to_flash": False,
    }
    a.output.write_text(json.dumps(report, indent=2) + "\n")
    print(report["status"])


if __name__ == "__main__":
    main()
