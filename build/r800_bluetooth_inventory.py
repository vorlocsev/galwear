#!/usr/bin/env python3
"""Offline Bluetooth HAL, transport and firmware candidates; no radio access."""
from __future__ import annotations
import re
import stat
import struct

from r800_android_userspace_preflight import guest_path, read_regular
from r800_art_launch import executable
from r800_display_inventory import parse_dtb, strings

PARTITIONS = ("vendor", "odm", "system", "product", "system_ext")
KERNEL_KEYS = ("CONFIG_BT", "CONFIG_BT_LE", "CONFIG_BT_HCIUART", "CONFIG_BT_HCIUART_H4",
               "CONFIG_BT_HCIUART_BCM", "CONFIG_BT_HCIUART_LL", "CONFIG_BT_HCIBTUSB",
               "CONFIG_BT_BCM", "CONFIG_RFKILL", "CONFIG_SERIAL_SAMSUNG")
MAX_SCAN = 4096
MAX_FILES = 128
MAX_BYTES = 128 * 1024 * 1024
LIB = re.compile(r"(?:libbt-vendor|libbluetooth|libbluetooth_jni|android\.hardware\.bluetooth@[0-9.]+(?:-impl)?)\.so")
FIRMWARE = re.compile(r"(?:.*\.(?:hcd|bts)|(?:bt|bluetooth|bcm|brcm|rtl|qca)[A-Za-z0-9_.-]*\.(?:bin|fw|tlv|nvm))", re.I)
CONFIG = re.compile(r"(?:bt_vendor|bt_stack|bt_did|bluetooth)[A-Za-z0-9_.-]*\.conf")


def dt_inventory(nodes):
    enabled, candidates = {}, []
    for path, props in nodes.items():
        parent = path.rsplit("/", 1)[0] or "/"
        status = strings(props.get("status", b""))
        enabled[path] = (not status or status in (["okay"], ["ok"])) and (
            path == "/" or enabled.get(parent, False))
        compat = strings(props.get("compatible", b""))
        clue = " ".join([path.rsplit("/", 1)[-1]] + compat).lower()
        if not any(term in clue for term in ("bluetooth", "bt-uart", "bt_uart", "rfkill", "hci", "brcm,bcm", "serial", "uart")):
            continue
        item = {"path": path, "compatible": compat, "enabled": enabled[path],
                "transport_candidate": any(x in clue for x in ("serial", "uart")),
                "bluetooth_candidate": any(x in clue for x in ("bluetooth", "bt-uart", "bt_uart", "hci", "brcm,bcm")),
                "properties": sorted(k for k in props if k in ("shutdown-gpios", "reset-gpios",
                    "device-wakeup-gpios", "host-wakeup-gpios", "clocks", "uart-has-rtscts",
                    "max-speed", "firmware-name", "vbat-supply", "vddio-supply"))}
        if "firmware-name" in props:
            item["firmware_names"] = strings(props["firmware-name"])
        if "max-speed" in props:
            if len(props["max-speed"]) != 4:
                raise ValueError("Invalid Bluetooth UART max-speed cell")
            item["max_speed"] = struct.unpack(">I", props["max-speed"])[0]
        candidates.append(item)
    return candidates


def config_inventory(raw):
    # Do not ingest persisted pairing databases or Bluetooth addresses.
    values = {}
    for line in raw.decode("utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if "=" not in line:
            continue
        key, value = (v.strip() for v in line.split("=", 1))
        if key in ("UartPort", "UartBaudRate", "FwPatchFilePath", "FwPatchFileName",
                   "FirmwareFile", "HciTransport", "BtTransport"):
            if key in values:
                raise ValueError("Duplicate Bluetooth transport configuration key")
            values[key] = value
    return values


def audit(root, init, vintf, inspect_elf, kernel_config=None, dtb=None):
    errors, services, libraries, firmware, configs = [], [], {}, {}, {}
    declared = [entry for doc in vintf["files"].values()
                if doc["kind"] == "manifest" and doc["type"] == "device"
                for entry in doc["entries"] if entry["name"] == "android.hardware.bluetooth"]
    for service in init.get("bluetooth_services", []):
        item = {"name": service["name"], "path": service["executable"], "elf": None,
                "interfaces": [o["args"] for o in service["options"] if o["name"] == "interface"]}
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
                ("/etc/bluetooth", CONFIG, None, "config"), ("/etc", CONFIG, None, "config"),
                ("/firmware", FIRMWARE, None, "firmware"),
                ("/etc/firmware", FIRMWARE, None, "firmware"),
                ("/firmware/brcm", FIRMWARE, None, "firmware"),
                ("/etc/firmware/brcm", FIRMWARE, None, "firmware")):
            directory = "/" + partition + suffix
            try:
                names = []
                for entry in guest_path(root, directory).iterdir():
                    scanned += 1
                    if scanned > MAX_SCAN:
                        raise ValueError("Bluetooth scan limit exceeded")
                    if pattern.fullmatch(entry.name):
                        names.append(entry.name)
                        if len(names) > MAX_FILES:
                            raise ValueError("Bluetooth candidate limit exceeded")
                for name in sorted(names):
                    if len(libraries) + len(firmware) + len(configs) >= MAX_FILES:
                        raise ValueError("Bluetooth file limit exceeded")
                    guest = directory + "/" + name
                    target = libraries if kind == "lib" else configs if kind == "config" else firmware
                    target[guest] = None
                    try:
                        path = guest_path(root, guest)
                        st = path.lstat()
                        if not stat.S_ISREG(st.st_mode) or not 0 < st.st_size <= 64 * 1024 * 1024:
                            raise ValueError("Invalid Bluetooth candidate file")
                        if kind == "firmware":
                            target[guest] = {"bytes": st.st_size, "controller_compatibility_verified": False}
                            continue
                        if total + st.st_size > MAX_BYTES:
                            raise ValueError("Bluetooth aggregate byte limit exceeded")
                        raw = read_regular(path, 128 * 1024 if kind == "config" else 64 * 1024 * 1024)
                        total += len(raw)
                        if kind == "config":
                            target[guest] = config_inventory(raw)
                        else:
                            info = inspect_elf(raw)
                            if info["abi"] != abi or info["elf_type"] != "ET_DYN" or not info["has_dynamic"]:
                                raise ValueError("Bluetooth library ELF ABI or type mismatch")
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
    for guest in ("/dev/rfkill", "/dev/ttySAC0", "/dev/ttySAC1", "/dev/ttySAC2", "/dev/ttySAC3", "/dev/ttyHS0"):
        try:
            nodes[guest] = stat.S_ISCHR(guest_path(root, guest).lstat().st_mode)
            if not nodes[guest]:
                errors.append(guest + ": not a character device")
        except FileNotFoundError:
            continue
        except (OSError, ValueError) as exc:
            errors.append(guest + ": " + str(exc))
    enabled_controller = any(item["enabled"] and item["bluetooth_candidate"] for item in dt)
    kernel = None if kernel_config is None else {key: kernel_config.get(key) for key in KERNEL_KEYS}
    return {"status": "STATIC_BLUETOOTH_INVENTORY_ONLY" if not errors and declared and
            any(s["elf"] for s in services) and any(libraries.values()) and enabled_controller and
            kernel and kernel["CONFIG_BT"] in ("y", "m") else "REVIEW_REQUIRED",
            "hal_declarations": declared, "services": services, "libraries": libraries,
            "firmware_candidates": firmware, "transport_configs": configs, "dt_candidates": dt,
            "device_nodes": nodes, "kernel_config": kernel, "errors": errors,
            "firmware_compatibility_verified": False, "hci_transport_verified": False,
            "hal_registered": False, "pairing_verified": False, "ble_verified": False,
            "safe_to_flash": False}
