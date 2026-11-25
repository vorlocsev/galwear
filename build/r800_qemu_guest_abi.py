#!/usr/bin/env python3
"""Boot a separate ABI diagnostic PID1 on an already-tested virt kernel.

The external six-entry CPIO replaces the embedded /init only in a new VM.
No hardware configuration, device or firmware image is modified.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess

from r800_qemu_abi_probe import EXPECTED as ABI_EXPECTED, inspect_result
from r800_qemu_system_init import run as boot, kernel_bytes
from r800_qemu_user_init import EXPECTED, HEARTBEAT_PREFIX

START = b"r800-abi-pid1: guest PID=1"
END = b"r800-abi-pid1: complete"
BINDER_EXPECTED = [b"r800-binder: " + name + b" version=8 mmap=PASS" for name in (b"binder", b"hwbinder", b"vndbinder")] + [b"r800-binder: transaction roundtrip=PASS distinct-processes=1", b"r800-binder: PASS"]
SHMEM_EXPECTED = [b"r800-shmem: ashmem size=65536 roundtrip=PASS",
                  b"r800-shmem: memfd size=65536 roundtrip=PASS seals=PASS",
                  b"r800-shmem: PASS"]


BIONIC_MARKER = b"r800-libc: bionic api=30 static"


def inspect_abi(log: bytes, bionic: bool = False) -> dict:
    lines = log.replace(b"\r\n", b"\n").splitlines()
    if lines.count(START) != 1 or lines.count(END) != 1:
        raise ValueError("Missing or duplicate ABI PID1 markers")
    start, end = lines.index(START), lines.index(END)
    init = lines.index(EXPECTED.rstrip(b"\n"))
    if not init < start < end:
        raise ValueError("Unexpected ABI PID1 marker order")
    libc_lines = [line for line in lines if line.startswith(b"r800-libc:")]
    if libc_lines != ([BIONIC_MARKER] if bionic else []):
        raise ValueError("Unexpected libc identity")
    abi_lines = [line for line in lines if line.startswith(b"r800-abi:")]
    if bionic and (not abi_lines or not start < lines.index(BIONIC_MARKER) < lines.index(abi_lines[0])):
        raise ValueError("Libc identity outside ABI startup window")
    if abi_lines != ABI_EXPECTED.splitlines():
        raise ValueError("Unexpected ABI stage sequence")
    if any(line.startswith(b"r800-abi:") for line in lines[:start] + lines[end:]):
        raise ValueError("ABI stages outside PID1 marker window")
    if any(line.startswith(HEARTBEAT_PREFIX) for line in lines[:end]):
        raise ValueError("Heartbeat before ABI completion")
    binder_lines = [line for line in lines if line.startswith(b"r800-binder:")]
    if binder_lines != BINDER_EXPECTED:
        raise ValueError("Unexpected Binder diagnostic sequence")
    abi_end = lines.index(ABI_EXPECTED.splitlines()[-1])
    if not abi_end < lines.index(binder_lines[0]) < lines.index(binder_lines[-1]) < end:
        raise ValueError("Binder stages outside ABI completion window")
    shmem_lines = [line for line in lines if line.startswith(b"r800-shmem:")]
    if shmem_lines != SHMEM_EXPECTED:
        raise ValueError("Unexpected shared memory diagnostic sequence")
    if not lines.index(binder_lines[-1]) < lines.index(shmem_lines[0]) < lines.index(shmem_lines[-1]) < end:
        raise ValueError("Shared memory stages outside ABI completion window")
    return {"ashmem_roundtrip_reported": True, "memfd_roundtrip_reported": True,
            "memfd_seals_reported": True, "shared_region_bytes": 65536,
            "binder_version_reported": 8, "binder_devices_checked": ["binder", "hwbinder", "vndbinder"],
            "binder_buffer_mapping_reported": True, "binder_transactions_tested": True,
            "binder_roundtrip_context": "binder", "binder_distinct_processes_reported": True,
            "bionic_tested": bionic, "guest_pid1_reported": True, "abi_completed_before_heartbeat": True,
            **inspect_result(b"\n".join(abi_lines) + b"\n", b"", 0)}


def verify_baseline(path: Path, kernel: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise ValueError("Missing baseline boot evidence")
    with path.open("rb") as f:
        data = f.read(65537)
    if len(data) > 65536:
        raise ValueError("Oversized baseline boot evidence")
    evidence = json.loads(data)
    digest = hashlib.sha256(kernel_bytes(kernel)).hexdigest()
    if not isinstance(evidence, dict) or (
        evidence.get("status") != "VIRT_EMBEDDED_PID1_BOOT_ONLY"
        or evidence.get("initramfs_mode") != "embedded"
        or evidence.get("generic_kernel_sha256") != digest
        or evidence.get("guest_progress_after_marker_verified") is not True
        or evidence.get("safe_to_flash") is not False
    ):
        raise ValueError("Baseline boot evidence does not match virt kernel")
    return digest


def read_bounded_json(path: Path) -> dict:
    if path.is_symlink() or not path.is_file():
        raise ValueError("Missing libc evidence")
    with path.open("rb") as stream:
        raw = stream.read(65537)
    if len(raw) > 65536:
        raise ValueError("Oversized libc evidence")
    result = json.loads(raw)
    if not isinstance(result, dict):
        raise ValueError("Invalid libc evidence")
    return result


def verify_bionic(compile_report: Path, glibc_report: Path, binary: Path, kernel_sha: str) -> dict:
    from r800_initramfs_spec import validate_init
    compiled = read_bounded_json(compile_report)
    glibc = read_bounded_json(glibc_report)
    sha = validate_init(binary)["sha256"]
    if (compiled.get("status") != "BIONIC_STATIC_COMPILE_ONLY"
            or compiled.get("ndk_revision") != "27.3.13750724"
            or compiled.get("android_api") != 30
            or compiled.get("init_sha256") != sha
            or compiled.get("safe_to_flash") is not False):
        raise ValueError("Bionic compile evidence mismatch")
    if (glibc.get("status") != "VIRT_GUEST_KERNEL_ABI_ONLY"
            or glibc.get("generic_kernel_sha256") != kernel_sha
            or glibc.get("guest_kernel_syscalls_tested") is not True
            or glibc.get("bionic_tested") is not False
            or glibc.get("init_sha256") == sha
            or glibc.get("safe_to_flash") is not False):
        raise ValueError("Matching successful glibc baseline required")
    return {"ndk_revision": compiled["ndk_revision"], "android_api": 30,
            "glibc_baseline_init_sha256": glibc.get("init_sha256"),
            "dynamic_android_linker_tested": False}


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--init", required=True, type=Path)
    p.add_argument("--compile-evidence", required=True, type=Path)
    p.add_argument("--kernel", required=True, type=Path)
    p.add_argument("--baseline", required=True, type=Path)
    p.add_argument("--out-dir", required=True, type=Path)
    p.add_argument("--report", required=True, type=Path)
    p.add_argument("--bionic-compile-evidence", type=Path)
    p.add_argument("--glibc-baseline", type=Path)
    a = p.parse_args()
    try:
        digest = verify_baseline(a.baseline, a.kernel)
        bionic = a.bionic_compile_evidence is not None
        if bionic != (a.glibc_baseline is not None):
            raise ValueError("Both Bionic and glibc evidence are required together")
        libc = verify_bionic(a.bionic_compile_evidence, a.glibc_baseline, a.init, digest) if bionic else {}
        evidence = boot(a.init, a.compile_evidence, a.kernel, a.out_dir)
        if evidence["generic_kernel_sha256"] != digest:
            raise ValueError("Virtual kernel changed after baseline verification")
        report = {**evidence, **inspect_abi((a.out_dir / "generic-console.log").read_bytes(), bionic), **libc,
                  "schema": "galwear-r800-virt-guest-abi-v1",
                  "status": "VIRT_GUEST_BIONIC_ABI_ONLY" if bionic else "VIRT_GUEST_KERNEL_ABI_ONLY",
                  "guest_kernel_syscalls_tested": True,
                  "external_diagnostic_initrd": True,
                  "parallel_cpu_execution_proven": False,
                  "safe_to_flash": False}
        rc = 0
    except (OSError, ValueError, IndexError, EOFError, subprocess.SubprocessError) as exc:
        report = {"status": "REJECT", "reason": str(exc),
                  "guest_kernel_syscalls_tested": False, "safe_to_flash": False}
        rc = 2
    a.report.write_text(json.dumps(report, indent=2) + "\n")
    print(report["status"])
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
