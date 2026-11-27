#!/usr/bin/env python3
"""Offline WLAN prerequisites; no radio access or saved network credentials."""
from __future__ import annotations
import re
import stat
import struct
from r800_android_userspace_preflight import guest_path, read_regular
from r800_art_launch import executable
from r800_display_inventory import parse_dtb, strings

PARTITIONS = ("vendor", "odm", "system", "product", "system_ext")
KERNEL_KEYS = ("CONFIG_WLAN", "CONFIG_CFG80211", "CONFIG_MAC80211", "CONFIG_MMC",
               "CONFIG_MMC_SDHCI", "CONFIG_MMC_DW", "CONFIG_BRCMFMAC",
               "CONFIG_BRCMFMAC_SDIO", "CONFIG_BCMDHD", "CONFIG_DHD", "CONFIG_RFKILL")
MAX_SCAN = 4096
MAX_FILES = 128
MAX_BYTES = 128 * 1024 * 1024
LIB = re.compile(r"(?:libwifi-hal(?:-[A-Za-z0-9_.-]+)?|libwpa_client|libwifi-system|android\.hardware\.wifi(?:\.supplicant|\.hostapd)?@[0-9.]+(?:-impl)?)\.so")
FIRMWARE = re.compile(r"(?:brcmfmac|bcmdhd|fw_bcmdhd|nvram|clm_blob|wlan|wifi)[A-Za-z0-9_.-]*\.(?:bin|txt|clm_blob|fw|conf)", re.I)
CONFIG = re.compile(r"(?:wpa_supplicant|wpa_supplicant_overlay|p2p_supplicant_overlay|hostapd)\.conf")
SAFE_CONFIG = {"ctrl_interface", "update_config", "ap_scan", "p2p_disabled",
               "wowlan_triggers", "driver_param", "pmf"}


def dt_inventory(nodes):
    enabled, candidates = {}, []
    for path, props in nodes.items():
        parent = path.rsplit("/", 1)[0] or "/"
        status = strings(props.get("status", b""))
        enabled[path] = (not status or status in (["okay"], ["ok"])) and (
            path == "/" or enabled.get(parent, False))
        compat = strings(props.get("compatible", b""))
        clue = " ".join([path.rsplit("/", 1)[-1]] + compat).lower()
        wlan = any(x in clue for x in ("wifi", "wi-fi", "wlan", "brcmfmac", "bcmdhd", "brcm,bcm43"))
        bus = any(x in clue for x in ("sdio", "mmc", "sdhci"))
        if not wlan and not bus:
            continue
        item = {"path": path, "compatible": compat, "enabled": enabled[path],
                "wlan_candidate": wlan, "sdio_candidate": bus,
                "properties": sorted(k for k in props if k in ("non-removable", "cap-sdio-irq",
                    "keep-power-in-suspend", "mmc-pwrseq", "vmmc-supply", "vqmmc-supply",
                    "host-wake-gpios", "interrupts", "firmware-name", "bus-width"))}
        if "firmware-name" in props:
            item["firmware_names"] = strings(props["firmware-name"])
        if "bus-width" in props:
            if len(props["bus-width"]) != 4:
                raise ValueError("Invalid SDIO bus-width cell")
            item["bus_width"] = struct.unpack(">I", props["bus-width"])[0]
        candidates.append(item)
    return candidates


def config_inventory(raw):
    # Only global allowlisted settings, never network blocks or passwords.
    values = {}
    for line in raw.decode("utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if "{" in line:
            break
        if "=" not in line:
            continue
        key, value = (x.strip() for x in line.split("=", 1))
        if key in SAFE_CONFIG:
            if key in values:
                raise ValueError("Duplicate WLAN global configuration key")
            # Omit arbitrary parameter strings; they can carry private data.
            values[key] = value if key in ("update_config", "ap_scan", "p2p_disabled", "pmf") and value in ("0", "1", "2") else "PRESENT"
    return values


def audit(root, init, vintf, inspect_elf, kernel_config=None, dtb=None):
    errors, services, libraries, firmware, configs = [], [], {}, {}, {}
    declared = [e for doc in vintf["files"].values()
                if doc["kind"] == "manifest" and doc["type"] == "device"
                for e in doc["entries"] if e["name"] in (
                    "android.hardware.wifi", "android.hardware.wifi.supplicant",
                    "android.hardware.wifi.hostapd")]
    for service in init.get("wifi_services", []):
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
                ("/etc/wifi", CONFIG, None, "config"),
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
                        raise ValueError("WLAN scan limit exceeded")
                    if pattern.fullmatch(entry.name):
                        names.append(entry.name)
                        if len(names) > MAX_FILES:
                            raise ValueError("WLAN candidate limit exceeded")
                for name in sorted(names):
                    if len(libraries) + len(firmware) + len(configs) >= MAX_FILES:
                        raise ValueError("WLAN file limit exceeded")
                    guest = directory + "/" + name
                    target = libraries if kind == "lib" else configs if kind == "config" else firmware
                    target[guest] = None
                    try:
                        path = guest_path(root, guest)
                        st = path.lstat()
                        if not stat.S_ISREG(st.st_mode) or not 0 < st.st_size <= 64 * 1024 * 1024:
                            raise ValueError("Invalid WLAN candidate file")
                        if kind == "firmware":
                            target[guest] = {"bytes": st.st_size, "chipset_compatibility_verified": False}
                            continue
                        if total + st.st_size > MAX_BYTES:
                            raise ValueError("WLAN aggregate byte limit exceeded")
                        raw = read_regular(path, 128 * 1024 if kind == "config" else 64 * 1024 * 1024)
                        total += len(raw)
                        if kind == "config":
                            target[guest] = config_inventory(raw)
                        else:
                            info = inspect_elf(raw)
                            if info["abi"] != abi or info["elf_type"] != "ET_DYN" or not info["has_dynamic"]:
                                raise ValueError("WLAN library ELF ABI or type mismatch")
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
    interfaces = []
    try:
        for i, entry in enumerate(guest_path(root, "/sys/class/net").iterdir()):
            if i >= MAX_SCAN:
                raise ValueError("Network interface scan limit exceeded")
            if re.fullmatch(r"(?:wlan|p2p|wifi)[0-9]+", entry.name):
                interfaces.append(entry.name)
    except FileNotFoundError:
        pass
    except (OSError, ValueError) as exc:
        errors.append(str(exc))
    kernel = None if kernel_config is None else {k: kernel_config.get(k) for k in KERNEL_KEYS}
    hal_names = {e["name"] for e in declared}
    controller = any(e["enabled"] and e["wlan_candidate"] for e in dt)
    supplicant = any(s["elf"] and "supplicant" in s["name"].lower() for s in services)
    return {"status": "STATIC_WIFI_INVENTORY_ONLY" if not errors and
            {"android.hardware.wifi", "android.hardware.wifi.supplicant"} <= hal_names and
            supplicant and any(libraries.values()) and controller and kernel and
            kernel["CONFIG_CFG80211"] in ("y", "m") else "REVIEW_REQUIRED",
            "hal_declarations": declared, "services": services, "libraries": libraries,
            "firmware_candidates": firmware, "global_config_evidence": configs,
            "dt_candidates": dt, "interface_names_snapshot": sorted(interfaces),
            "kernel_config": kernel, "errors": errors,
            "firmware_compatibility_verified": False, "sdio_transport_verified": False,
            "hal_registered": False, "association_verified": False, "network_verified": False,
            "safe_to_flash": False}
