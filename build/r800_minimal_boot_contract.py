#!/usr/bin/env python3
"""Check declared minimal boot arguments and effective kernel config; no boot proof."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess

from r800_dtb_memory_audit import get, strings
from r800_embedded_dtb import MINIMAL_BOOTARGS

REQUIRED = ("CONFIG_ARM64", "CONFIG_BLK_DEV_INITRD", "CONFIG_BINFMT_ELF",
            "CONFIG_PRINTK", "CONFIG_SERIAL_SAMSUNG", "CONFIG_SERIAL_SAMSUNG_CONSOLE")


def audit_config(text: str) -> dict:
    config = {}
    for line in text.splitlines():
        if line.startswith("CONFIG_") and "=" in line:
            key, value = line.split("=", 1)
        elif line.startswith("# CONFIG_") and line.endswith(" is not set"):
            key, value = line[2:-11], "n"
        else:
            continue
        if key in config:
            raise ValueError("Duplicate Kconfig setting: " + key)
        config[key] = value
    for key in REQUIRED:
        if config.get(key) != "y":
            raise ValueError("Required built-in Kconfig missing: " + key)
    source = config.get("CONFIG_INITRAMFS_SOURCE", "")
    if not source.startswith('"/') or not source.endswith('/initramfs.list"'):
        raise ValueError("Expected validated embedded initramfs list")
    if config.get("CONFIG_CMDLINE") != '""':
        raise ValueError("Unexpected built-in kernel command line")
    if any(config.get(key) == "y" for key in ("CONFIG_CMDLINE_FORCE", "CONFIG_CMDLINE_EXTEND")):
        raise ValueError("Kernel may override or extend declared DTB arguments")
    return {"required_builtin_options": list(REQUIRED),
            "embedded_source_selected": True, "builtin_cmdline_empty": True}


def audit(dtb: Path, config: Path) -> dict:
    for p in (dtb, config):
        if p.is_symlink() or not p.is_file() or not 0 < p.stat().st_size <= 1024 * 1024:
            raise ValueError("Invalid audit input")
    if strings(dtb, "/chosen", "bootargs") != MINIMAL_BOOTARGS:
        raise ValueError("Expected exact minimal bootargs")
    if {"linux,initrd-start", "linux,initrd-end"} & set(get(dtb, "-p", "/chosen").splitlines()):
        raise ValueError("External initrd pointers still present")
    data = config.read_bytes()
    return {"schema": "galwear-r800-minimal-boot-contract-v1",
            "status": "STATIC_BOOT_CONTRACT_ONLY",
            "bootargs": MINIMAL_BOOTARGS, "dtb_sha256": hashlib.sha256(dtb.read_bytes()).hexdigest(),
            "effective_config_sha256": hashlib.sha256(data).hexdigest(),
            "config": audit_config(data.decode("utf-8")),
            "blockers": ["SBOOT_MAY_REWRITE_CHOSEN_AT_RUNTIME",
                         "KERNEL_MAY_PROBE_OR_WRITE_HARDWARE_BEFORE_INIT",
                         "RDINIT_FAILURE_CAN_TRIGGER_KERNEL_ROOT_FALLBACK",
                         "UART_ACCESS_AND_INIT_EXECUTION_UNVERIFIED"],
            "boot_tested": False, "device_contacted": False, "safe_to_flash": False}


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--dtb", type=Path, required=True)
    p.add_argument("--config", type=Path, required=True)
    p.add_argument("--report", type=Path, required=True)
    a = p.parse_args()
    try:
        result = audit(a.dtb, a.config)
        rc = 0
    except (ValueError, OSError, subprocess.SubprocessError) as exc:
        result = {"status": "REJECT", "reason": str(exc), "safe_to_flash": False}
        rc = 2
    a.report.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(result["status"])
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
