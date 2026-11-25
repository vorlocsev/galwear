#!/usr/bin/env python3
"""Read-only NFC controller and Android HAL inventory; no tag or payment access."""
from __future__ import annotations

import re
import stat
from r800_android_userspace_preflight import guest_path, read_regular
from r800_art_launch import executable
from r800_display_inventory import parse_dtb, strings

PARTITIONS = ("vendor", "odm", "system", "product", "system_ext")
MAX_SCAN = 4096
MAX_FILES = 128
MAX_BYTES = 128 * 1024 * 1024
LIB = re.compile(r"(?:nfc\.[A-Za-z0-9_.-]+|lib(?:nfc-nci|nfc_nci|nfc-nxp|nfc_nxp|nfc_jni|nfc_st|nfc_samsung)|android\.hardware\.nfc@[0-9.]+(?:-impl)?)\.so")
CONFIG = re.compile(r"(?:libnfc|nfc)[A-Za-z0-9_.-]*\.conf", re.I)
FIRMWARE = re.compile(r"(?:nfc|pn54|pn55|pn56|sn100|st21|s3fwrn)[A-Za-z0-9_.-]*\.(?:bin|fw|img|so)", re.I)
KERNEL_KEYS = ("CONFIG_NFC", "CONFIG_NFC_NCI", "CONFIG_NFC_NCI_UART",
               "CONFIG_NFC_NXP_NCI", "CONFIG_NFC_NXP_NCI_I2C",
               "CONFIG_NFC_PN544", "CONFIG_NFC_PN544_I2C", "CONFIG_NFC_ST21NFCA",
               "CONFIG_I2C", "CONFIG_SPI")
SAFE_SETTINGS = {"NFC_NCI_DEV_NODE", "NXP_NFC_DEV_NODE", "NFC_DEVICE_NODE",
                 "NXP_NFC_FW_PATH", "NXP_NFC_FW_NAME", "NCI_HAL_MODULE",
                 "NXP_NFC_CHIP", "NFC_CHIP_TYPE", "NFC_TRANSPORT"}


def dt_inventory(nodes):
    enabled, candidates = {}, []
    for path, props in nodes.items():
        parent = path.rsplit("/", 1)[0] or "/"
        status = strings(props.get("status", b""))
        enabled[path] = (not status or status in (["okay"], ["ok"])) and (
            path == "/" or enabled.get(parent, False))
        compatible = strings(props.get("compatible", b""))
        clue = " ".join([path.rsplit("/", 1)[-1]] + compatible).lower()
        if not any(term in clue for term in ("nfc", "pn544", "pn547", "pn553", "pn557",
                                             "st21", "s3fwrn", "sn100")):
            continue
        parent_props = nodes.get(parent, {})
        parent_compat = strings(parent_props.get("compatible", b""))
        parent_clue = " ".join([parent.rsplit("/", 1)[-1]] + parent_compat).lower()
        item = {"path": path, "compatible": compatible, "enabled": enabled[path],
                "parent": parent, "transport_candidates": [
                    bus for bus in ("i2c", "spi", "uart") if bus in parent_clue],
                "properties": sorted(k for k in props if k in (
                    "reg", "interrupts", "irq-gpios", "enable-gpios", "reset-gpios",
                    "firmware-gpios", "wake-gpios", "vdd-supply", "firmware-name"))}
        if "firmware-name" in props:
            item["firmware_names"] = strings(props["firmware-name"])
        candidates.append(item)
    return candidates


def config_inventory(raw):
    values = {}
    for line in raw.decode("utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if "=" not in line:
            continue
        key, value = (part.strip() for part in line.split("=", 1))
        if key in SAFE_SETTINGS:
            if key in values:
                raise ValueError("Duplicate NFC configuration key")
            values[key] = "PRESENT" if value else "EMPTY"
    return values


def audit(root, init, vintf, inspect_elf, kernel_config=None, dtb=None):
    errors, services, libraries, firmware, configs = [], [], {}, {}, {}
    declared = [entry for doc in vintf["files"].values()
                if doc["kind"] == "manifest" and doc["type"] == "device"
                for entry in doc["entries"] if entry["name"] == "android.hardware.nfc"]
    for service in init.get("nfc_services", []):
        item = {"name": service["name"], "path": service["executable"], "elf": None}
        services.append(item)
        try:
            item["elf"] = executable(root, item["path"])
        except (OSError, ValueError) as exc:
            errors.append(item["name"] + ": " + str(exc))
    scanned = total = 0
    for partition in PARTITIONS:
        for suffix, pattern, abi, kind in (
                ("/lib", LIB, "arm", "lib"), ("/lib64", LIB, "arm64", "lib"),
                ("/lib/hw", LIB, "arm", "lib"), ("/lib64/hw", LIB, "arm64", "lib"),
                ("/etc", CONFIG, None, "config"), ("/etc/nfc", CONFIG, None, "config"),
                ("/firmware", FIRMWARE, None, "firmware"),
                ("/etc/firmware", FIRMWARE, None, "firmware"),
                ("/firmware/nfc", FIRMWARE, None, "firmware")):
            directory = "/" + partition + suffix
            try:
                names = []
                for entry in guest_path(root, directory).iterdir():
                    scanned += 1
                    if scanned > MAX_SCAN:
                        raise ValueError("NFC scan limit exceeded")
                    if pattern.fullmatch(entry.name):
                        names.append(entry.name)
                        if len(names) > MAX_FILES:
                            raise ValueError("NFC candidate limit exceeded")
                for name in sorted(names):
                    if len(libraries) + len(firmware) + len(configs) >= MAX_FILES:
                        raise ValueError("NFC file limit exceeded")
                    guest = directory + "/" + name
                    target = libraries if kind == "lib" else configs if kind == "config" else firmware
                    target[guest] = None
                    try:
                        path = guest_path(root, guest)
                        st = path.lstat()
                        if not stat.S_ISREG(st.st_mode) or not 0 < st.st_size <= 64 * 1024 * 1024:
                            raise ValueError("Invalid NFC candidate file")
                        if kind == "firmware":
                            target[guest] = {"bytes": st.st_size, "controller_compatibility_verified": False}
                            continue
                        if total + st.st_size > MAX_BYTES:
                            raise ValueError("NFC aggregate byte limit exceeded")
                        raw = read_regular(path, 128 * 1024 if kind == "config" else 64 * 1024 * 1024)
                        total += len(raw)
                        if kind == "config":
                            target[guest] = config_inventory(raw)
                        else:
                            info = inspect_elf(raw)
                            if info["abi"] != abi or info["elf_type"] != "ET_DYN" or not info["has_dynamic"]:
                                raise ValueError("NFC library ELF ABI or type mismatch")
                            target[guest] = {"abi": abi, "needed": info["needed"]}
                    except (OSError, ValueError) as exc:
                        errors.append(guest + ": " + str(exc))
            except FileNotFoundError:
                continue
            except (OSError, ValueError) as exc:
                errors.append(directory + ": " + str(exc))
    dt = []
    if dtb is not None:
        try:
            dt = dt_inventory(parse_dtb(dtb))
        except ValueError as exc:
            errors.append(str(exc))
    nodes = {}
    for guest in ("/dev/pn544", "/dev/pn547", "/dev/pn553", "/dev/nfc",
                  "/dev/sec-nfc", "/dev/st21nfc"):
        try:
            nodes[guest] = stat.S_ISCHR(guest_path(root, guest).lstat().st_mode)
            if not nodes[guest]:
                errors.append(guest + ": not a character device")
        except FileNotFoundError:
            continue
        except (OSError, ValueError) as exc:
            errors.append(guest + ": " + str(exc))
    return {"status": "STATIC_NFC_INVENTORY_ONLY" if not errors and declared and
            any(s["elf"] for s in services) and any(libraries.values()) and
            any(item["enabled"] for item in dt) else "REVIEW_REQUIRED",
            "hal_declarations": declared, "services": services, "libraries": libraries,
            "firmware_candidates": firmware, "config_evidence": configs,
            "dt_candidates": dt, "device_nodes": nodes,
            "kernel_config": None if kernel_config is None else {k: kernel_config.get(k) for k in KERNEL_KEYS},
            "errors": errors, "controller_identified": False, "nci_transport_verified": False,
            "firmware_compatibility_verified": False, "hal_registered": False,
            "tag_read_verified": False, "secure_element_verified": False, "safe_to_flash": False}
