#!/usr/bin/env python3
"""Offline GNSS HAL, transport and firmware inventory; no live positioning data."""
from __future__ import annotations
import re
import stat
import struct

from r800_android_userspace_preflight import guest_path, read_regular
from r800_art_launch import executable
from r800_display_inventory import parse_dtb, strings

PARTITIONS = ("vendor", "odm", "system", "product", "system_ext")
KERNEL_KEYS = ("CONFIG_GNSS", "CONFIG_GNSS_SERIAL", "CONFIG_GNSS_SIRF",
               "CONFIG_GNSS_UBX_SERIAL", "CONFIG_SERIAL_SAMSUNG", "CONFIG_SERIAL_DEV_BUS",
               "CONFIG_PPS", "CONFIG_RFKILL")
MAX_SCAN = 4096
MAX_FILES = 128
MAX_BYTES = 128 * 1024 * 1024
LIB = re.compile(r"(?:gps\.[A-Za-z0-9_.-]+|lib(?:gps|gnss|loc_eng|loc_core|loc_api_v02|gnsspps|glgps)|android\.hardware\.gnss@[0-9.]+(?:-impl)?)\.so")
FIRMWARE = re.compile(r"(?:gps|gnss|glgps|sirf|ublox)[A-Za-z0-9_.-]*\.(?:bin|fw|img|patch)", re.I)
CONFIG = re.compile(r"(?:gps|gnss|gps_debug|izat|flp)[A-Za-z0-9_.-]*\.conf")
SAFE_SETTINGS = {"SUPL_HOST", "SUPL_PORT", "SUPL_VER", "SUPL_MODE", "NTP_SERVER",
                 "XTRA_SERVER_1", "XTRA_SERVER_2", "XTRA_SERVER_3", "LPP_PROFILE",
                 "GPS_LOCK", "CAPABILITIES", "INTERMEDIATE_POS", "ACCURACY_THRES"}


def dt_inventory(nodes):
    enabled, candidates = {}, []
    for path, props in nodes.items():
        parent = path.rsplit("/", 1)[0] or "/"
        status = strings(props.get("status", b""))
        enabled[path] = (not status or status in (["okay"], ["ok"])) and (
            path == "/" or enabled.get(parent, False))
        compat = strings(props.get("compatible", b""))
        clue = " ".join([path.rsplit("/", 1)[-1]] + compat).lower()
        receiver = any(x in clue for x in ("gps", "gnss", "sirf", "u-blox", "ublox"))
        transport = any(x in clue for x in ("serial", "uart", "pps"))
        if not receiver and not transport:
            continue
        item = {"path": path, "compatible": compat, "enabled": enabled[path],
                "receiver_candidate": receiver, "transport_candidate": transport,
                "properties": sorted(k for k in props if k in ("enable-gpios", "reset-gpios",
                    "shutdown-gpios", "vcc-supply", "vbackup-supply", "clocks",
                    "current-speed", "max-speed", "firmware-name", "interrupts"))}
        if "firmware-name" in props:
            item["firmware_names"] = strings(props["firmware-name"])
        for key in ("current-speed", "max-speed"):
            if key in props:
                if len(props[key]) != 4:
                    raise ValueError("Invalid GNSS serial speed cell")
                item[key] = struct.unpack(">I", props[key])[0]
        candidates.append(item)
    return candidates


def config_inventory(raw):
    # Retain only allowlisted settings and presence, not server addresses or location.
    values = {}
    for line in raw.decode("utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if "=" not in line:
            continue
        key, value = (part.strip() for part in line.split("=", 1))
        if key in SAFE_SETTINGS:
            if key in values:
                raise ValueError("Duplicate GNSS configuration key")
            values[key] = ("EMPTY" if not value else "PRESENT")
    return values


def audit(root, init, vintf, inspect_elf, kernel_config=None, dtb=None):
    errors, services, libraries, firmware, configs = [], [], {}, {}, {}
    declared = [entry for doc in vintf["files"].values()
                if doc["kind"] == "manifest" and doc["type"] == "device"
                for entry in doc["entries"] if entry["name"] == "android.hardware.gnss"]
    for service in init.get("gnss_services", []):
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
                ("/etc", CONFIG, None, "config"), ("/etc/gps", CONFIG, None, "config"),
                ("/firmware", FIRMWARE, None, "firmware"),
                ("/etc/firmware", FIRMWARE, None, "firmware"),
                ("/firmware/gnss", FIRMWARE, None, "firmware")):
            directory = "/" + partition + suffix
            try:
                names = []
                for entry in guest_path(root, directory).iterdir():
                    scanned += 1
                    if scanned > MAX_SCAN:
                        raise ValueError("GNSS scan limit exceeded")
                    if pattern.fullmatch(entry.name):
                        names.append(entry.name)
                        if len(names) > MAX_FILES:
                            raise ValueError("GNSS candidate limit exceeded")
                for name in sorted(names):
                    if len(libraries) + len(firmware) + len(configs) >= MAX_FILES:
                        raise ValueError("GNSS file limit exceeded")
                    guest = directory + "/" + name
                    target = libraries if kind == "lib" else configs if kind == "config" else firmware
                    target[guest] = None
                    try:
                        path = guest_path(root, guest)
                        st = path.lstat()
                        if not stat.S_ISREG(st.st_mode) or not 0 < st.st_size <= 64 * 1024 * 1024:
                            raise ValueError("Invalid GNSS candidate file")
                        if kind == "firmware":
                            target[guest] = {"bytes": st.st_size, "receiver_compatibility_verified": False}
                            continue
                        if total + st.st_size > MAX_BYTES:
                            raise ValueError("GNSS aggregate byte limit exceeded")
                        raw = read_regular(path, 128 * 1024 if kind == "config" else 64 * 1024 * 1024)
                        total += len(raw)
                        if kind == "config":
                            target[guest] = config_inventory(raw)
                        else:
                            info = inspect_elf(raw)
                            if info["abi"] != abi or info["elf_type"] != "ET_DYN" or not info["has_dynamic"]:
                                raise ValueError("GNSS library ELF ABI or type mismatch")
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
    for guest in ("/dev/gnss0", "/dev/gps", "/dev/ttySAC0", "/dev/ttySAC1",
                  "/dev/ttySAC2", "/dev/ttySAC3", "/dev/pps0"):
        try:
            nodes[guest] = stat.S_ISCHR(guest_path(root, guest).lstat().st_mode)
            if not nodes[guest]:
                errors.append(guest + ": not a character device")
        except FileNotFoundError:
            continue
        except (OSError, ValueError) as exc:
            errors.append(guest + ": " + str(exc))
    receiver = any(item["enabled"] and item["receiver_candidate"] for item in dt)
    return {"status": "STATIC_GNSS_INVENTORY_ONLY" if not errors and declared and
            any(s["elf"] for s in services) and any(libraries.values()) and receiver
            else "REVIEW_REQUIRED",
            "hal_declarations": declared, "services": services, "libraries": libraries,
            "firmware_candidates": firmware, "config_evidence": configs,
            "dt_candidates": dt, "device_nodes": nodes,
            "kernel_config": None if kernel_config is None else {k: kernel_config.get(k) for k in KERNEL_KEYS},
            "errors": errors, "receiver_identified": False, "transport_verified": False,
            "firmware_compatibility_verified": False, "hal_registered": False,
            "satellite_fix_verified": False, "location_service_verified": False,
            "safe_to_flash": False}
