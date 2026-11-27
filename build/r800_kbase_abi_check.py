#!/usr/bin/env python3
"""Pinned R800 KBASE header layout checks; compile only, never issue ioctls."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

BASE = "50db73fc799f20a7120a8b5f653b16cc123d856f"
PINS = {
    "mali_kbase_ioctl.h": "9926939fb81a3357254254913dfad8c6530eb50e",
    "mali_kbase_core_linux.c": "f74a6621696b27688f830cf084b9a50447d25ef9",
    "mali_kbase_mem_linux.c": "b2398a12259f8ad4978390868b518d401887237d",
    "mali_base_kernel.h": "f8bd86f11e0f79711f6b207c63d14bde7eaf1aa9",
}
# direction, command number, size, declaration, offsets
LAYOUT = (
    ("VERSION_CHECK", 3, 0, 4, "struct kbase_ioctl_version_check", {"major":0,"minor":2}),
    ("SET_FLAGS", 1, 1, 4, "struct kbase_ioctl_set_flags", {"create_flags":0}),
    ("GET_GPUPROPS", 1, 3, 16, "struct kbase_ioctl_get_gpuprops", {"buffer":0,"size":8,"flags":12}),
    ("GET_DDK_VERSION", 1, 13, 16, "struct kbase_ioctl_get_ddk_version", {"version_buffer":0,"size":8,"padding":12}),
    ("MEM_IMPORT", 3, 22, 24, "union kbase_ioctl_mem_import",
     {"in.flags":0,"in.phandle":8,"in.type":16,"in.padding":20,"out.flags":0,"out.gpu_va":8,"out.va_pages":16}),
    ("MEM_FREE", 1, 7, 8, "struct kbase_ioctl_mem_free", {"gpu_addr":0}),
    ("FENCE_VALIDATE", 1, 25, 4, "struct kbase_ioctl_fence_validate", {"fd":0}),
)

def git_blob(raw):
    return hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()

def read_pinned(directory):
    result = {}
    for name, digest in PINS.items():
        raw = (directory/name).read_bytes()
        if git_blob(raw) != digest:
            raise ValueError("Unexpected pinned kernel blob: "+name)
        result[name] = raw
    return result

def source_evidence(files):
    core = files["mali_kbase_core_linux.c"].decode()
    mem = files["mali_kbase_mem_linux.c"].decode()
    base = files["mali_base_kernel.h"].decode()
    checks = {
        "shared_compat_dispatch": bool(re.search(r"\.unlocked_ioctl\s*=\s*kbase_ioctl\s*,\s*\.compat_ioctl\s*=\s*kbase_ioctl\s*,",core)),
        "version_dispatch": bool(re.search(r"case KBASE_IOCTL_VERSION_CHECK:\s*KBASE_HANDLE_IOCTL_INOUT\(KBASE_IOCTL_VERSION_CHECK,\s*kbase_api_handshake,",core)),
        "mem_import_dispatch": bool(re.search(r"case KBASE_IOCTL_MEM_IMPORT:\s*KBASE_HANDLE_IOCTL_INOUT\(KBASE_IOCTL_MEM_IMPORT,\s*kbase_api_mem_import,",core)),
        "import_user_pointer": "u64_to_user_ptr(import->in.phandle)" in core,
        "umm_type": bool(re.search(r"\bBASE_MEM_IMPORT_TYPE_UMM\s*=\s*2\s*,",base)),
        "umm_fd_pointer": bool(re.search(r"case BASE_MEM_IMPORT_TYPE_UMM:\s*\{\s*int fd;\s*if \(get_user\(fd, \(int __user \*\)phandle\)\)",mem)),
        "dma_buf_get": "dma_buf_get(fd)" in mem,
    }
    if not all(checks.values()):
        raise ValueError("Pinned source evidence incomplete: "+str(checks))
    return checks

def generate():
    lines = ['#include <stddef.h>', '#include "mali_kbase_ioctl.h"',
             '_Static_assert(BASE_UK_VERSION_MAJOR == 11 && BASE_UK_VERSION_MINOR == 13, "UK version");',
             '_Static_assert(KBASE_IOCTL_TYPE == 0x80, "ioctl type");']
    for name, direction, number, size, decl, offsets in LAYOUT:
        code = direction<<30 | size<<16 | 0x80<<8 | number
        lines.append(f'_Static_assert(sizeof({decl}) == {size}, "{name} size");')
        lines.append(f'_Static_assert(KBASE_IOCTL_{name} == 0x{code:08x}UL, "{name} ioctl");')
        for field, offset in offsets.items():
            lines.append(f'_Static_assert(offsetof({decl}, {field}) == {offset}, "{name} {field}");')
    return "\n".join(lines)+"\n"

def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ("source-dir","ndk","scratch"):
        p.add_argument("--"+name, type=Path, required=True)
    p.add_argument("--source-sha", required=True)
    a = p.parse_args()
    if not re.fullmatch(r"[0-9a-f]{40}", a.source_sha):
        raise ValueError("Expected full GalWear SHA")
    files = read_pinned(a.source_dir)
    checks = source_evidence(files)
    a.scratch.mkdir(parents=True, exist_ok=False)
    header = a.scratch/"mali_kbase_ioctl.h"
    header.write_bytes(files[header.name])
    unit = a.scratch/"layout.c"
    unit.write_text(generate())
    bindir = a.ndk/"toolchains/llvm/prebuilt/linux-x86_64/bin"
    targets = ("armv7a-linux-androideabi28-clang","aarch64-linux-android28-clang")
    for target in targets:
        subprocess.run([str(bindir/target), "-std=gnu11", "-fsyntax-only", str(unit)],
                       check=True, timeout=30)
    report = {"status":"KBASE_PINNED_HEADER_LAYOUT_ONLY", "source_sha":a.source_sha,
              "kernel_sha":BASE, "source_blobs":PINS, "uk_version":[11,13],
              "compiled_targets":list(targets), "source_evidence":checks,
              "ioctls":{name:{"size":size,"code":f"0x{direction<<30 | size<<16 | 0x80<<8 | number:08x}",
                               "offsets":offsets}
                        for name,direction,number,size,decl,offsets in LAYOUT},
              "donor_userspace_verified":False, "compat_ioctl_runtime_verified":False,
              "dma_buf_import_verified":False, "gpu_hardware_verified":False, "safe_to_flash":False}
    (a.scratch/"kbase-abi-evidence.json").write_text(json.dumps(report, indent=2, sort_keys=True)+"\n")
    print(json.dumps(report, sort_keys=True))

if __name__ == "__main__":
    main()
