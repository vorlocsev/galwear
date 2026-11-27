#!/usr/bin/env python3
"""Offline power, thermal and suspend evidence. Never writes sysfs or sets limits."""
from __future__ import annotations

import re
from r800_android_userspace_preflight import guest_path, read_regular
from r800_art_launch import executable
from r800_display_inventory import parse_dtb, strings

PARTITIONS = ("vendor", "odm", "system", "product", "system_ext")
MAX_SCAN = 4096
MAX_FILES = 128
MAX_BYTES = 128 * 1024 * 1024
LIB = re.compile(r"(?:power\.[A-Za-z0-9_.-]+|thermal\.[A-Za-z0-9_.-]+|lib(?:power|powerhal|thermal|thermalhal|suspend|autosuspend)|android\.hardware\.(?:power|thermal)@[0-9.]+(?:-impl)?|android\.system\.suspend@[0-9.]+(?:-impl)?)\.so")
KERNEL_KEYS = ("CONFIG_PM", "CONFIG_PM_SLEEP", "CONFIG_SUSPEND", "CONFIG_CPU_IDLE",
               "CONFIG_CPU_FREQ", "CONFIG_CPU_FREQ_DEFAULT_GOV_SCHEDUTIL",
               "CONFIG_CPU_FREQ_GOV_INTERACTIVE", "CONFIG_CPU_FREQ_GOV_ONDEMAND",
               "CONFIG_CPU_FREQ_GOV_SCHEDUTIL", "CONFIG_PM_DEVFREQ", "CONFIG_PM_OPP",
               "CONFIG_THERMAL", "CONFIG_THERMAL_OF", "CONFIG_CPU_THERMAL",
               "CONFIG_EXYNOS_THERMAL", "CONFIG_WAKELOCK", "CONFIG_PM_WAKELOCKS",
               "CONFIG_REGULATOR", "CONFIG_COMMON_CLK")
HAL_NAMES = ("android.hardware.power", "android.hardware.thermal", "android.system.suspend")
SYSFS = (
    ("/sys/devices/system/cpu/cpufreq", r"policy[0-9]+",
     {"scaling_driver", "scaling_governor", "scaling_available_governors",
      "scaling_available_frequencies", "scaling_min_freq", "scaling_max_freq", "cpuinfo_cur_freq"}),
    ("/sys/class/devfreq", r"[A-Za-z0-9_.:@-]{1,128}",
     {"governor", "available_governors", "available_frequencies", "min_freq", "max_freq", "cur_freq"}),
    ("/sys/class/thermal", r"(?:thermal_zone|cooling_device)[0-9]+",
     {"type", "temp", "mode", "policy", "available_policies", "cur_state", "max_state"}),
    ("/sys/devices/system/cpu/cpuidle", r"cpuidle",
     {"current_driver", "current_governor", "current_governor_ro"}),
)


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
        if "operating-points" in props or "operating-points-v2" in props or "opp-hz" in props or "opp-table" in clue:
            kinds.append("opp")
        if "thermal" in clue or "trip-points" in clue or "thermal-sensors" in props:
            kinds.append("thermal")
        if any(t in clue for t in ("idle-state", "idle-states", "power-domain")) or "cpu-idle-states" in props:
            kinds.append("idle_or_domain")
        if "wakeup-source" in props:
            kinds.append("wakeup")
        if not kinds:
            continue
        candidates.append({"path": path, "compatible": compatible, "enabled": enabled[path],
                           "kinds": kinds, "property_names": sorted(k for k in props if k in (
                               "operating-points", "operating-points-v2", "opp-hz", "opp-microvolt",
                               "thermal-sensors", "temperature", "hysteresis", "cooling-device",
                               "cpu-idle-states", "entry-latency-us", "exit-latency-us",
                               "min-residency-us", "power-domains", "wakeup-source"))})
    return candidates


def sysfs_inventory(root, errors):
    result = {}
    scanned = 0
    for directory, pattern, attrs in SYSFS:
        try:
            base = guest_path(root, directory)
            entries = [base] if directory.endswith("/cpuidle") else base.iterdir()
            for entry in entries:
                scanned += 1
                if scanned > MAX_SCAN or len(result) >= MAX_FILES:
                    raise ValueError("Power sysfs inventory limit exceeded")
                if not re.fullmatch(pattern, entry.name):
                    continue
                guest = directory if directory.endswith("/cpuidle") else directory + "/" + entry.name
                try:
                    resolved = guest_path(root, guest)
                    names = []
                    for attr in resolved.iterdir():
                        scanned += 1
                        if scanned > MAX_SCAN:
                            raise ValueError("Power sysfs attribute limit exceeded")
                        if attr.name in attrs or (directory.endswith("/thermal") and
                                re.fullmatch(r"trip_point_[0-9]+_(?:temp|type|hyst)", attr.name)):
                            names.append(attr.name)
                    result[guest] = sorted(names)
                except (OSError, ValueError) as exc:
                    errors.append(guest + ": " + str(exc))
        except FileNotFoundError:
            continue
        except (OSError, ValueError) as exc:
            errors.append(directory + ": " + str(exc))
    sleep = {}
    for path in ("/sys/power/state", "/sys/power/mem_sleep"):
        try:
            value = read_regular(guest_path(root, path), 256).decode("ascii")
            sleep[path] = [word for word in value.split() if word.strip("[]") in
                           ("freeze", "standby", "mem", "disk", "s2idle", "shallow", "deep")]
        except FileNotFoundError:
            continue
        except (OSError, ValueError) as exc:
            errors.append(path + ": " + str(exc))
    return result, sleep


def audit(root, init, vintf, inspect_elf, kernel_config=None, dtb=None):
    errors, services, libraries = [], [], {}
    declared = [entry for doc in vintf["files"].values()
                if doc["kind"] == "manifest" and doc["type"] == "device"
                for entry in doc["entries"] if entry["name"] in HAL_NAMES]
    for service in init.get("power_services", []):
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
                        raise ValueError("Power library scan limit exceeded")
                    if LIB.fullmatch(entry.name):
                        names.append(entry.name)
                        if len(names) > MAX_FILES:
                            raise ValueError("Power candidate limit exceeded")
                for name in sorted(names):
                    if len(libraries) >= MAX_FILES:
                        raise ValueError("Power library limit exceeded")
                    guest = directory + "/" + name
                    libraries[guest] = None
                    try:
                        path = guest_path(root, guest)
                        size = path.lstat().st_size
                        if total + size > MAX_BYTES:
                            raise ValueError("Power ELF aggregate budget exceeded")
                        raw = read_regular(path, 64 * 1024 * 1024)
                        total += len(raw)
                        info = inspect_elf(raw)
                        if info["abi"] != abi or info["elf_type"] != "ET_DYN" or not info["has_dynamic"]:
                            raise ValueError("Power library ELF ABI or type mismatch")
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
    snapshots, sleep = sysfs_inventory(root, errors)
    kernel = None if kernel_config is None else {k: kernel_config.get(k) for k in KERNEL_KEYS}
    kinds = {k for item in dt if item["enabled"] for k in item["kinds"]}
    hal_names = {e["name"] for e in declared}
    return {"status": "STATIC_POWER_INVENTORY_ONLY" if not errors and
            {"android.hardware.power", "android.hardware.thermal"} <= hal_names and
            any(s["elf"] for s in services) and any(libraries.values()) and
            {"opp", "thermal"} <= kinds and kernel and
            all(kernel[k] in ("y", "m") for k in ("CONFIG_PM", "CONFIG_CPU_FREQ", "CONFIG_THERMAL"))
            else "REVIEW_REQUIRED",
            "hal_declarations": declared, "services": services, "libraries": libraries,
            "dt_candidates": dt, "enabled_dt_kinds": sorted(kinds),
            "sysfs_attribute_snapshot": snapshots, "sleep_modes_snapshot": sleep,
            "kernel_config": kernel, "errors": errors,
            "power_hal_registered": False, "thermal_hal_registered": False,
            "cpufreq_runtime_verified": False, "devfreq_runtime_verified": False,
            "thermal_protection_verified": False, "suspend_resume_verified": False,
            "battery_drain_verified": False, "safe_to_flash": False}
