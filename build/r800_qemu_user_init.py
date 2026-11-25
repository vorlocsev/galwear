#!/usr/bin/env python3
"""Run the compiled non-release AArch64 /init under QEMU user mode.

Only CI-built, trusted project code is intended as input. QEMU user mode
translates guest syscalls; it is not a security sandbox or an Exynos emulator.
No device, kernel Image, firmware or block device is supplied.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

from r800_initramfs_spec import validate_init

SCHEMA = "galwear-r800-qemu-user-init-v1"
EXPECTED = b"r800-readonly-init: NON-RELEASE smoke image; no eMMC mount, no Wear OS handover\n"
TIMEOUT = 8
TRACE_LINE = re.compile(r"^\s*\d+\s+([A-Za-z_][A-Za-z_0-9]*)\(")


def inspect_trace(stdout: bytes, stderr: bytes, timed_out: bool) -> dict:
    if not timed_out:
        raise ValueError("Minimal init exited instead of remaining idle")
    if stdout != EXPECTED:
        raise ValueError("Unexpected or missing init console message")
    trace = stderr.decode("ascii", errors="strict")
    calls = []
    write_ok = False
    sleep_ok = False
    for line in trace.splitlines():
        if not line.strip():
            continue
        match = TRACE_LINE.match(line)
        if not match:
            raise ValueError("Unrecognized QEMU syscall trace line")
        name = match[1]
        if name not in ("write", "nanosleep"):
            raise ValueError("Unexpected guest syscall: " + name)
        calls.append(name)
        if name == "write":
            expected = r"^\s*\d+\s+write\(1,[^,]+," + str(len(EXPECTED)) + r"\)\s*=\s*" + str(len(EXPECTED)) + r"\s*$"
            if not re.fullmatch(expected, line):
                raise ValueError("Unexpected write syscall arguments or return")
            write_ok = True
        elif re.search(r"\)\s*=\s*0\s*$", line):
            sleep_ok = True
        elif "=" in line:
            raise ValueError("Unexpected nanosleep failure")
    if not write_ok or not sleep_ok or not calls or calls[0] != "write" or calls.count("write") != 1:
        raise ValueError("Expected one console write and at least one completed sleep")
    return {"console_message_exact": True, "completed_nanosleep": True,
            "observed_guest_syscalls": calls, "terminated_by_host_timeout": True}


def run(binary: Path, evidence: Path) -> dict:
    elf = validate_init(binary)
    if evidence.is_symlink() or not evidence.is_file() or evidence.stat().st_size > 65536:
        raise ValueError("Invalid compile evidence")
    report = json.loads(evidence.read_text())
    if report.get("status") != "NON_RELEASE_INITRAMFS_SPEC_ONLY" or report.get("init") != elf:
        raise ValueError("Compiled init differs from compile evidence")
    version = subprocess.run(["qemu-aarch64", "--version"], capture_output=True, check=True,
                             text=True, timeout=5).stdout.splitlines()[0]
    proc = subprocess.Popen(["qemu-aarch64", "-strace", str(binary.resolve())],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    timed_out = False
    try:
        stdout, stderr = proc.communicate(timeout=TIMEOUT)
    except subprocess.TimeoutExpired:
        timed_out = True
        proc.kill()
        stdout, stderr = proc.communicate(timeout=5)
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
    observed = inspect_trace(stdout, stderr, timed_out)
    if validate_init(binary) != elf:
        raise ValueError("Init changed during execution")
    return {"schema": SCHEMA, "status": "QEMU_USER_INIT_RUNTIME_ONLY",
            "init_sha256": elf["sha256"], "qemu_version": version,
            "stdout_sha256": hashlib.sha256(stdout).hexdigest(), **observed,
            "kernel_boot_tested": False, "exynos9110_emulated": False,
            "device_contacted": False, "safe_to_flash": False}


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--init", required=True, type=Path)
    p.add_argument("--compile-evidence", required=True, type=Path)
    p.add_argument("--report", required=True, type=Path)
    a = p.parse_args()
    try:
        result = run(a.init, a.compile_evidence)
        rc = 0
    except (OSError, ValueError, subprocess.SubprocessError, IndexError) as exc:
        result = {"schema": SCHEMA, "status": "REJECT", "reason": str(exc),
                  "kernel_boot_tested": False, "safe_to_flash": False}
        rc = 2
    a.report.write_text(json.dumps(result, indent=2) + "\n")
    print(result["status"])
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
