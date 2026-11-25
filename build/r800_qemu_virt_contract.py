#!/usr/bin/env python3
"""Check effective QEMU virt-only config, never approve hardware flashing."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from r800_storage_isolation import parse
from r800_initramfs_spec import validate_init

REQUIRED = ("STAGING", "ASHMEM", "SHMEM", "TMPFS", "MEMFD_CREATE", "DEVTMPFS", "ANDROID", "ANDROID_BINDER_IPC", "FUTEX", "POSIX_TIMERS", "MULTIUSER", "ADVISE_SYSCALLS", "SMP", "ARM64", "ARM64_4K_PAGES", "ARM_AMBA", "ARM_GIC_V3",
            "ARM_ARCH_TIMER", "ARM_PSCI_FW", "ARCH_VEXPRESS", "PRINTK",
            "TTY", "SERIAL_AMBA_PL011", "SERIAL_AMBA_PL011_CONSOLE",
            "BINFMT_ELF", "BLK_DEV_INITRD", "INITRAMFS_COMPRESSION_NONE")
FORBIDDEN = ("ARCH_EXYNOS", "ARCH_EXYNOS9", "MMC", "SCSI", "MTD", "USB",
             "NET", "MODULES", "PSTORE", "INITRAMFS_FORCE", "ANDROID_BINDERFS", "ANDROID_VSOC", "CMDLINE_FORCE", "CMDLINE_EXTEND")


def inspect(text: str, source: str) -> dict:
    config = parse(text)
    for key in REQUIRED:
        if config.get("CONFIG_" + key) != "y":
            raise ValueError("Missing virt built-in CONFIG_" + key)
    for key in FORBIDDEN:
        if config.get("CONFIG_" + key, "n") != "n":
            raise ValueError("Unexpected enabled CONFIG_" + key)
    if config.get("CONFIG_ANDROID_BINDER_DEVICES") != '"binder,hwbinder,vndbinder"':
        raise ValueError("Unexpected legacy Binder device list")
    if config.get("CONFIG_NR_CPUS") != "2":
        raise ValueError("Virt config must allow exactly two CPUs")
    if config.get("CONFIG_INITRAMFS_SOURCE") != '"' + source + '"':
        raise ValueError("Embedded list changed")
    if config.get("CONFIG_CMDLINE") != '""':
        raise ValueError("Unexpected built-in command line")
    return {"status": "VIRT_CONFIG_STATIC_ONLY", "required": list(REQUIRED),
            "disabled": list(FORBIDDEN), "nr_cpus": 2,
            "config_sha256": hashlib.sha256(text.encode()).hexdigest(),
            "r800_hardware_config": False, "safe_to_flash": False}


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--config", type=Path, required=True)
    p.add_argument("--list", type=Path, required=True)
    p.add_argument("--report", type=Path, required=True)
    a = p.parse_args()
    try:
        if not a.list.is_absolute() or a.list.name != "initramfs.list":
            raise ValueError("Invalid list path")
        elf = validate_init(a.list.parent / "init")
        result = inspect(a.config.read_text(), str(a.list))
        result["init_sha256"] = elf["sha256"]
        rc = 0
    except (OSError, ValueError) as exc:
        result = {"status": "REJECT", "reason": str(exc), "safe_to_flash": False}
        rc = 2
    a.report.write_text(json.dumps(result, indent=2) + "\n")
    print(result["status"])
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
