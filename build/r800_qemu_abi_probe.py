#!/usr/bin/env python3
"""Run a trusted CI-built static AArch64 ABI probe in QEMU user mode only."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess

from r800_initramfs_spec import validate_init

EXPECTED = (
    b"r800-abi: mmap-zero-fill PASS bytes=1048576\n"
    b"r800-abi: pthread-shared-memory PASS distinct-tid=1\n"
    b"r800-abi: mprotect-munmap PASS\n"
    b"r800-abi: monotonic-sleep PASS\n"
    b"r800-abi: PASS\n"
)


def inspect_result(stdout: bytes, stderr: bytes, returncode: int) -> dict:
    if returncode != 0:
        raise ValueError(f"ABI probe exited with status {returncode}")
    if stderr:
        raise ValueError("Unexpected ABI probe stderr")
    if stdout != EXPECTED:
        raise ValueError("Missing, reordered or unexpected ABI probe output")
    return {"anonymous_mapping_bytes": 1048576, "zero_fill_verified": True,
            "distinct_worker_tid_reported": True, "shared_memory_roundtrip": True,
            "mprotect_munmap_reported": True, "monotonic_sleep_reported": True,
            "stdout_sha256": hashlib.sha256(stdout).hexdigest()}


def run(binary: Path) -> dict:
    elf = validate_init(binary)
    version = subprocess.run(["qemu-aarch64", "--version"], capture_output=True,
                             check=True, text=True, timeout=5).stdout.splitlines()[0]
    result = subprocess.run(["qemu-aarch64", str(binary.resolve())],
                            capture_output=True, timeout=30, check=False)
    if validate_init(binary) != elf:
        raise ValueError("ABI probe changed during execution")
    return {"schema": "galwear-r800-aarch64-abi-v1", "status": "QEMU_USER_ABI_ONLY",
            "binary_sha256": elf["sha256"], "qemu_version": version,
            **inspect_result(result.stdout, result.stderr, result.returncode),
            "guest_kernel_syscalls_tested": False, "exynos9110_emulated": False,
            "parallel_cpu_execution_proven": False, "device_contacted": False,
            "safe_to_flash": False}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--probe", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()
    try:
        report = run(args.probe)
        rc = 0
    except (OSError, ValueError, subprocess.SubprocessError, IndexError) as exc:
        report = {"status": "REJECT", "reason": str(exc), "safe_to_flash": False}
        rc = 2
    args.report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(report["status"])
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
