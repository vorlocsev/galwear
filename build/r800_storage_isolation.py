#!/usr/bin/env python3
"""Experimental storage-driver isolation for disposable R800 kernel configs.

No hardware access, no firmware packaging. This does not prove the absence of
vendor-specific writes, bootloader writes, or other hardware side effects.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re

SCHEMA = "galwear-r800-storage-isolation-v1"
DISABLE = (
    "CONFIG_MMC", "CONFIG_MMC_BLOCK", "CONFIG_MMC_DW", "CONFIG_MMC_DW_EXYNOS",
    "CONFIG_PWRSEQ_EMMC", "CONFIG_SCSI", "CONFIG_BLK_DEV_SD",
    "CONFIG_SCSI_UFSHCD", "CONFIG_SCSI_UFSHCD_PLATFORM",
    "CONFIG_ATA", "CONFIG_BLK_DEV_NVME", "CONFIG_MTD",
    "CONFIG_USB_STORAGE", "CONFIG_USB_UAS", "CONFIG_USB_CONFIGFS_MASS_STORAGE",
    "CONFIG_USB_MASS_STORAGE", "CONFIG_MODULES", "CONFIG_PSTORE",
    "CONFIG_BLK_DEV_LOOP", "CONFIG_BLK_DEV_DM", "CONFIG_SWAP",
)
BASELINE_ENABLED = ("CONFIG_MMC", "CONFIG_SCSI", "CONFIG_MODULES", "CONFIG_PSTORE")
RETAIN = ("CONFIG_ARM64", "CONFIG_BLK_DEV_INITRD", "CONFIG_BINFMT_ELF",
          "CONFIG_PRINTK", "CONFIG_SERIAL_SAMSUNG_CONSOLE")
SETTING = re.compile(r"^(CONFIG_[A-Za-z0-9_]+)=(.*)$")
UNSET = re.compile(r"^# (CONFIG_[A-Za-z0-9_]+) is not set$")


def parse(text: str) -> dict[str, str]:
    values = {}
    for line in text.splitlines():
        setting, unset = SETTING.fullmatch(line), UNSET.fullmatch(line)
        if setting:
            key, value = setting.groups()
        elif unset:
            key, value = unset[1], "n"
        else:
            continue
        if key in values:
            raise ValueError("Duplicate Kconfig symbol: " + key)
        values[key] = value
    return values


def prerequisites(values: dict[str, str]) -> None:
    for key in RETAIN:
        if values.get(key) != "y":
            raise ValueError("Missing required built-in: " + key)
    source = values.get("CONFIG_INITRAMFS_SOURCE", "")
    if not source.startswith('"/') or not source.endswith('/initramfs.list"'):
        raise ValueError("Isolation requires explicit embedded initramfs")


def prepare(text: str) -> str:
    values = parse(text)
    prerequisites(values)
    if any(values.get(key) != "y" for key in BASELINE_ENABLED):
        raise ValueError("Unexpected baseline storage configuration")
    lines = []
    for line in text.splitlines(keepends=True):
        key = line.split("=", 1)[0]
        if key in DISABLE:
            if values[key] not in ("y", "m", "n"):
                raise ValueError("Unexpected non-boolean storage setting: " + key)
            line = "# " + key + " is not set\n"
        lines.append(line)
    result = "".join(lines)
    verify(result)
    return result


def verify(text: str) -> dict:
    values = parse(text)
    prerequisites(values)
    for key in DISABLE:
        # olddefconfig can omit symbols whose dependencies are disabled.
        if values.get(key, "n") != "n":
            raise ValueError("Storage isolation symbol still enabled: " + key)
    return {
        "schema": SCHEMA,
        "status": "STATIC_SELECTED_STORAGE_DRIVERS_DISABLED",
        "checked_disabled_symbols": list(DISABLE),
        "retained_builtin_symbols": list(RETAIN),
        "config_sha256": hashlib.sha256(text.encode()).hexdigest(),
        "limitations": [
            "MMC_DISABLE_ALSO_REMOVES_SDIO_SUPPORT",
            "VENDOR_DIRECT_STORAGE_PATHS_NOT_EXHAUSTIVELY_AUDITED",
            "SBOOT_AND_HARDWARE_SIDE_EFFECTS_UNVERIFIED",
            "NO_DEVICE_BOOT_OR_WRITE_TRACE",
        ],
        "storage_write_impossible_proven": False,
        "boot_tested": False,
        "safe_to_flash": False,
    }


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("mode", choices=("prepare", "verify"))
    p.add_argument("--config", required=True, type=Path)
    p.add_argument("--report", type=Path)
    a = p.parse_args()
    try:
        if (a.config.is_symlink() or not a.config.is_file()
                or a.config.name != ".config"
                or not 0 < a.config.stat().st_size <= 1024 * 1024):
            raise ValueError("Expected disposable kernel O= .config")
        text = a.config.read_text()
        if a.mode == "prepare":
            if a.report is not None:
                raise ValueError("Report is only for effective config verification")
            a.config.write_text(prepare(text))
            print("Prepared experimental isolation config")
        else:
            result = verify(text)
            if a.report:
                a.report.write_text(json.dumps(result, indent=2) + "\n")
            print(result["status"])
    except (OSError, ValueError) as exc:
        print("REJECT:", exc)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
