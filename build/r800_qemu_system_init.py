#!/usr/bin/env python3
"""Generic ARM64 virt boot test, deliberately NOT an Exynos/R800 kernel test."""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
from pathlib import Path
import subprocess
import time

from r800_cpio_audit import inspect_cpio, MAX_ARCHIVE_BYTES
from r800_initramfs_spec import validate_init
from r800_qemu_user_init import EXPECTED, HEARTBEAT_PREFIX, inspect_heartbeats

SCHEMA = "galwear-r800-generic-arm64-system-v1"
MAX_KERNEL = 128 * 1024 * 1024
TIMEOUT = 90
MAX_LOG = 8 * 1024 * 1024


def create_archive(binary: Path) -> bytes:
    validate_init(binary)
    entries = [
        ("dev", 0o040755, b"", 0, 0),
        ("dev/console", 0o020600, b"", 5, 1),
        ("proc", 0o040555, b"", 0, 0),
        ("sys", 0o040555, b"", 0, 0),
        ("data", 0o040755, b"", 0, 0),
        ("init", 0o100755, binary.read_bytes(), 0, 0),
        ("TRAILER!!!", 0, b"", 0, 0),
    ]
    out = bytearray()
    for ino, (name, mode, payload, major, minor) in enumerate(entries, 1):
        pathname = name.encode("ascii") + b"\0"
        fields = (ino, mode, 0, 0, 2 if mode & 0o170000 == 0o040000 else 1,
                  0, len(payload), 0, 0, major, minor, len(pathname), 0)
        out.extend(b"070701" + b"".join(f"{x:08x}".encode() for x in fields))
        out.extend(pathname)
        out.extend(bytes((-len(out)) % 4))
        out.extend(payload)
        out.extend(bytes((-len(out)) % 4))
    return bytes(out)


def inspect_console(log: bytes, timed_out: bool) -> dict:
    normalized = log.replace(b"\r\n", b"\n")
    lines = normalized.splitlines()
    marker = EXPECTED.rstrip(b"\n")
    if not timed_out:
        raise ValueError("Virtual machine exited before host timeout")
    if lines.count(marker) != 1:
        raise ValueError("Expected exactly one minimal init marker")
    idx = lines.index(marker)
    if not any(b"Run /init as init process" in line for line in lines[:idx]):
        raise ValueError("No kernel evidence of launching /init")
    if any(b"Kernel panic" in line or b"Attempted to kill init" in line
           or b"Failed to execute /init" in line for line in lines):
        raise ValueError("Kernel panic or init execution failure")
    if any(line.startswith(HEARTBEAT_PREFIX) for line in lines[:idx]):
        raise ValueError("Heartbeat before startup marker")
    count = inspect_heartbeats([line for line in lines[idx + 1:]
                                if line.startswith(HEARTBEAT_PREFIX)])
    return {"kernel_launched_init": True, "console_marker_exact": True,
            "heartbeat_count": count, "heartbeat_sequence_verified": True,
            "qemu_process_alive_until_host_timeout": True,
            "guest_progress_after_marker_verified": True,
            "guest_alive_at_timeout_proven": False}


def kernel_bytes(path: Path) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise ValueError("Invalid generic kernel input")
    with path.open("rb") as f:
        magic = f.read(2)
    opener = gzip.open if magic == b"\x1f\x8b" else open
    with opener(path, "rb") as f:
        raw = f.read(MAX_KERNEL + 1)
    if not 64 <= len(raw) <= MAX_KERNEL or raw[56:60] != b"ARM\x64":
        raise ValueError("Expected bounded uncompressed or gzip ARM64 Linux Image")
    return raw


def verify_embedded(raw: bytes, archive: Path, binary: Path) -> dict:
    evidence = inspect_cpio(archive, binary)
    with archive.open("rb") as stream:
        data = stream.read(MAX_ARCHIVE_BYTES + 1)
    if not 0 < len(data) <= MAX_ARCHIVE_BYTES or hashlib.sha256(data).hexdigest() != evidence["archive_sha256"]:
        raise ValueError("Embedded CPIO changed after audit")
    offset = raw.find(data)
    if offset < 0 or raw.find(data, offset + 1) >= 0:
        raise ValueError("Audited CPIO missing or ambiguous in virt Image")
    return {**evidence, "image_offset": offset}


def run(binary: Path, compile_evidence: Path, kernel: Path, out: Path,
        embedded_archive: Path | None = None) -> dict:
    elf = validate_init(binary)
    if compile_evidence.is_symlink() or not compile_evidence.is_file():
        raise ValueError("Invalid compile evidence")
    with compile_evidence.open("rb") as stream:
        spec_raw = stream.read(65537)
    if len(spec_raw) > 65536:
        raise ValueError("Compile evidence too large")
    spec = json.loads(spec_raw)
    if not isinstance(spec, dict) or spec.get("status") != "NON_RELEASE_INITRAMFS_SPEC_ONLY" or spec.get("init") != elf:
        raise ValueError("Init does not match compile evidence")
    raw = kernel_bytes(kernel)
    out.mkdir(exist_ok=False)
    image = out / "generic-Image"
    image.write_bytes(raw)
    if embedded_archive is None:
        archive = out / "initramfs.cpio"
        archive.write_bytes(create_archive(binary))
        cpio = inspect_cpio(archive, binary)
    else:
        archive = embedded_archive
        cpio = verify_embedded(raw, archive, binary)
    if cpio["embedded_init_sha256"] != elf["sha256"]:
        raise ValueError("Archive init hash mismatch")
    version = subprocess.run(["qemu-system-aarch64", "--version"], check=True,
                             capture_output=True, text=True, timeout=5).stdout.splitlines()[0]
    command = [
        "qemu-system-aarch64", "-machine", "virt,gic-version=3,accel=tcg",
        "-cpu", "cortex-a53", "-smp", "2", "-m", "512M",
        "-nodefaults", "-no-reboot", "-display", "none", "-monitor", "none",
        "-serial", "stdio", "-nic", "none",
        "-kernel", str(image.resolve()),
        "-append", "console=ttyAMA0 rdinit=/init ro loglevel=7 panic=-1",
    ]
    if embedded_archive is None:
        command += ["-initrd", str(archive.resolve())]
    timed_out = False
    log_path = out / "generic-console.log"
    with log_path.open("wb") as stream:
        proc = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=stream,
                                stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic() + TIMEOUT
            while proc.poll() is None:
                if log_path.stat().st_size > MAX_LOG:
                    raise ValueError("Virtual console exceeded log limit")
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    timed_out = True
                    break
                try:
                    proc.wait(timeout=min(0.25, remaining))
                except subprocess.TimeoutExpired:
                    pass
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=5)
            if log_path.stat().st_size > MAX_LOG:
                stream.truncate(MAX_LOG)
                raise ValueError("Virtual console exceeded log limit; artifact truncated")
    observed = inspect_console(log_path.read_bytes(), timed_out)
    if validate_init(binary) != elf:
        raise ValueError("Init changed during virtual boot")
    return {"schema": SCHEMA, "status": "VIRT_EMBEDDED_PID1_BOOT_ONLY" if embedded_archive else "GENERIC_ARM64_PID1_BOOT_ONLY",
            "initramfs_mode": "embedded" if embedded_archive else "external",
            "archive_image_offset": cpio.get("image_offset"),
            "generic_kernel_sha256": hashlib.sha256(raw).hexdigest(),
            "init_sha256": elf["sha256"], "archive_sha256": cpio["archive_sha256"],
            "qemu_version": version, **observed,
            "r800_kernel_boot_tested": False, "exynos9110_emulated": False,
            "device_contacted": False, "safe_to_flash": False}


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--init", required=True, type=Path)
    p.add_argument("--compile-evidence", required=True, type=Path)
    p.add_argument("--generic-kernel", required=True, type=Path)
    p.add_argument("--embedded-archive", type=Path)
    p.add_argument("--out-dir", required=True, type=Path)
    p.add_argument("--report", required=True, type=Path)
    a = p.parse_args()
    try:
        report = run(a.init, a.compile_evidence, a.generic_kernel, a.out_dir, a.embedded_archive)
        rc = 0
    except (OSError, ValueError, subprocess.SubprocessError, IndexError, EOFError) as exc:
        report = {"schema": SCHEMA, "status": "REJECT", "reason": str(exc),
                  "r800_kernel_boot_tested": False, "safe_to_flash": False}
        rc = 2
    a.report.write_text(json.dumps(report, indent=2) + "\n")
    print(report["status"])
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
