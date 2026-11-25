#!/usr/bin/env python3
"""Offline battery, charger and PMIC inventory; never changes charging limits."""
from __future__ import annotations
import re
from r800_android_userspace_preflight import guest_path, read_regular
from r800_art_launch import executable
from r800_display_inventory import parse_dtb, strings

PARTITIONS = ("vendor", "odm", "system", "product", "system_ext")
MAX_SCAN = 4096
MAX_FILES = 128
MAX_BYTES = 128 * 1024 * 1024
LIB = re.compile(r"(?:lib(?:healthd|healthhalutils|healthloop|batteryservice)|health\.[A-Za-z0-9_.-]+|android\.hardware\.health@[0-9.]+(?:-impl)?)\.so")
KERNEL_KEYS = ("CONFIG_POWER_SUPPLY", "CONFIG_BATTERY", "CONFIG_CHARGER",
               "CONFIG_REGULATOR", "CONFIG_MFD", "CONFIG_I2C", "CONFIG_THERMAL",
               "CONFIG_BATTERY_SAMSUNG", "CONFIG_BATTERY_SEC", "CONFIG_WIRELESS_CHARGER")
SUPPLY_TYPES = {"Battery", "Wireless", "USB", "Mains", "Unknown", "USB_DCP",
                "USB_CDP", "USB_ACA", "USB_C", "USB_PD", "USB_PD_DRP"}
ATTRIBUTES = {"type", "status", "health", "present", "online", "capacity",
              "voltage_now", "current_now", "temp", "charge_full", "charge_full_design",
              "charge_counter", "technology", "constant_charge_current_max",
              "constant_charge_voltage_max", "input_current_limit"}


def dt_inventory(nodes):
    enabled, candidates = {}, []
    for path, props in nodes.items():
        parent = path.rsplit("/", 1)[0] or "/"
        status = strings(props.get("status", b""))
        enabled[path] = (not status or status in (["okay"], ["ok"])) and (
            path == "/" or enabled.get(parent, False))
        compatible = strings(props.get("compatible", b""))
        clue = " ".join([path.rsplit("/", 1)[-1]] + compatible).lower()
        kinds = []
        for kind, terms in (("battery", ("battery", "fuel-gauge", "fuel_gauge", "fuelgauge")),
                            ("charger", ("charger", "charging")),
                            ("wireless", ("wireless-charg", "wireless_charg", "wpc", "qi-charg")),
                            ("pmic", ("pmic", "regulator", "s2mps", "s2mpu"))):
            if any(term in clue for term in terms):
                kinds.append(kind)
        if not kinds:
            continue
        candidates.append({"path": path, "compatible": compatible, "enabled": enabled[path],
                           "kinds": kinds, "properties": sorted(k for k in props if k in
                               ("reg", "interrupts", "monitored-battery", "power-supplies",
                                "battery-supply", "vin-supply", "vdd-supply", "wakeup-source",
                                "charge-full-design-microamp-hours", "voltage-min-design-microvolt",
                                "voltage-max-design-microvolt", "constant-charge-current-max-microamp",
                                "constant-charge-voltage-max-microvolt"))})
    return candidates


def supply_inventory(root, errors):
    result = {}
    try:
        directory = guest_path(root, "/sys/class/power_supply")
        for i, entry in enumerate(directory.iterdir()):
            if i >= MAX_SCAN or len(result) >= MAX_FILES:
                raise ValueError("Power supply scan limit exceeded")
            if not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", entry.name):
                continue
            guest = "/sys/class/power_supply/" + entry.name
            try:
                path = guest_path(root, guest)
                attrs = []
                for j, attr in enumerate(path.iterdir()):
                    if j >= MAX_SCAN:
                        raise ValueError("Power supply attribute limit exceeded")
                    if attr.name in ATTRIBUTES:
                        attrs.append(attr.name)
                supply_type = None
                if "type" in attrs:
                    raw = read_regular(guest_path(root, guest + "/type"), 256)
                    value = raw.decode("ascii").strip()
                    supply_type = value if value in SUPPLY_TYPES else "UNRECOGNIZED"
                result[guest] = {"type": supply_type, "attribute_names": sorted(attrs)}
            except (OSError, ValueError) as exc:
                errors.append(guest + ": " + str(exc))
    except FileNotFoundError:
        pass
    except (OSError, ValueError) as exc:
        errors.append(str(exc))
    return result


def audit(root, init, vintf, inspect_elf, kernel_config=None, dtb=None):
    errors, services, libraries = [], [], {}
    declared = [e for doc in vintf["files"].values()
                if doc["kind"] == "manifest" and doc["type"] == "device"
                for e in doc["entries"] if e["name"] == "android.hardware.health"]
    for service in init.get("health_services", []):
        item = {"name": service["name"], "path": service["executable"], "elf": None}
        services.append(item)
        try:
            item["elf"] = executable(root, item["path"])
        except (OSError, ValueError) as exc:
            errors.append(item["name"] + ": " + str(exc))
    scanned = total = 0
    for partition in PARTITIONS:
        for suffix, abi in (("/lib", "arm"), ("/lib64", "arm64"),
                            ("/lib/hw", "arm"), ("/lib64/hw", "arm64")):
            directory = "/" + partition + suffix
            try:
                names = []
                for entry in guest_path(root, directory).iterdir():
                    scanned += 1
                    if scanned > MAX_SCAN:
                        raise ValueError("Health library scan limit exceeded")
                    if LIB.fullmatch(entry.name):
                        names.append(entry.name)
                        if len(names) > MAX_FILES:
                            raise ValueError("Health candidate limit exceeded")
                for name in sorted(names):
                    if len(libraries) >= MAX_FILES:
                        raise ValueError("Health library limit exceeded")
                    guest = directory + "/" + name
                    libraries[guest] = None
                    try:
                        path = guest_path(root, guest)
                        size = path.lstat().st_size
                        if total + size > MAX_BYTES:
                            raise ValueError("Health ELF aggregate budget exceeded")
                        raw = read_regular(path, 64 * 1024 * 1024)
                        total += len(raw)
                        info = inspect_elf(raw)
                        if info["abi"] != abi or info["elf_type"] != "ET_DYN" or not info["has_dynamic"]:
                            raise ValueError("Health library ELF ABI or type mismatch")
                        libraries[guest] = {"abi": abi, "needed": info["needed"]}
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
    supplies = supply_inventory(root, errors)
    kinds = {k for item in dt if item["enabled"] for k in item["kinds"]}
    missing = sorted({"battery", "charger", "wireless", "pmic"} - kinds)
    kernel = None if kernel_config is None else {k: kernel_config.get(k) for k in KERNEL_KEYS}
    return {"status": "STATIC_HEALTH_INVENTORY_ONLY" if not errors and declared and
            any(s["elf"] for s in services) and any(libraries.values()) and not missing and
            kernel and kernel["CONFIG_POWER_SUPPLY"] in ("y", "m") else "REVIEW_REQUIRED",
            "hal_declarations": declared, "services": services, "libraries": libraries,
            "dt_candidates": dt, "missing_dt_candidate_kinds": missing,
            "power_supply_snapshot": supplies, "kernel_config": kernel, "errors": errors,
            "health_hal_registered": False, "battery_reporting_verified": False,
            "wireless_charging_verified": False, "pmic_verified": False,
            "charging_safety_verified": False, "safe_to_flash": False}
