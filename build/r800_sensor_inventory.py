#!/usr/bin/env python3
"""Offline sensor HAL and device metadata; no sensor readings or calibration writes."""
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
LIB = re.compile(r"(?:sensors\.[A-Za-z0-9_.-]+|lib(?:sensor|sensors|sensorservice|sensorhub|sensorndkbridge)|android\.hardware\.sensors@[0-9.]+(?:-impl)?)\.so")
TYPES = {
    "accelerometer": ("accelerometer", "accel", "in_accel"),
    "gyroscope": ("gyroscope", "gyro", "anglvel"),
    "barometer": ("barometer", "pressure", "baro"),
    "ambient_light": ("ambient-light", "light-sensor", "illuminance", "als"),
    "heart_rate": ("heart-rate", "heart_rate", "heartrate", "ppg", "hrm"),
    "sensor_hub": ("sensorhub", "sensor-hub", "sensor_hub", "ssp"),
}
KERNEL_KEYS = ("CONFIG_IIO", "CONFIG_IIO_BUFFER", "CONFIG_IIO_TRIGGER", "CONFIG_INPUT",
               "CONFIG_INPUT_EVDEV", "CONFIG_I2C", "CONFIG_SPI", "CONFIG_SENSORS_SSP")


def classify(clue):
    return [kind for kind, terms in TYPES.items()
            if any(re.search(r"(?:^|[^a-z0-9])" + re.escape(t) + r"(?:$|[^a-z0-9])",
                             clue.lower()) for t in terms)]


def dt_inventory(nodes):
    enabled, candidates = {}, []
    for path, props in nodes.items():
        parent = path.rsplit("/", 1)[0] or "/"
        status = strings(props.get("status", b""))
        enabled[path] = (not status or status in (["okay"], ["ok"])) and (
            path == "/" or enabled.get(parent, False))
        compatible = strings(props.get("compatible", b""))
        clue = " ".join([path.rsplit("/", 1)[-1]] + compatible)
        kinds = classify(clue)
        if not kinds:
            continue
        candidates.append({"path": path, "compatible": compatible, "enabled": enabled[path],
                           "kinds": kinds, "properties": sorted(k for k in props if k in
                               ("reg", "interrupts", "interrupt-parent", "reset-gpios",
                                "vdd-supply", "vddio-supply", "mount-matrix", "wakeup-source"))})
    return candidates


def iio_inventory(root, errors):
    result = {}
    try:
        for i, entry in enumerate(guest_path(root, "/sys/bus/iio/devices").iterdir()):
            if i >= MAX_SCAN or len(result) >= MAX_FILES:
                raise ValueError("IIO device scan limit exceeded")
            if not re.fullmatch(r"iio:device[0-9]+", entry.name):
                continue
            guest = "/sys/bus/iio/devices/" + entry.name
            try:
                resolved = guest_path(root, guest)
                channels = []
                for j, node in enumerate(resolved.iterdir()):
                    if j >= 1024:
                        raise ValueError("IIO channel scan limit exceeded")
                    # Names only; never read raw, input, scale or buffer values.
                    if re.fullmatch(r"in_[a-zA-Z0-9_]{1,100}_(?:raw|input|scale)", node.name):
                        channels.append(node.name)
                kinds = sorted({kind for channel in channels for kind in classify(channel)})
                result[guest] = {"channel_attribute_names": sorted(channels), "kinds": kinds}
            except (OSError, ValueError) as exc:
                errors.append(guest + ": " + str(exc))
    except FileNotFoundError:
        pass
    except (OSError, ValueError) as exc:
        errors.append(str(exc))
    return result


def audit(root, init, vintf, inspect_elf, kernel_config=None, dtb=None):
    errors, services, libraries, nodes = [], [], {}, {}
    declared = [e for doc in vintf["files"].values()
                if doc["kind"] == "manifest" and doc["type"] == "device"
                for e in doc["entries"] if e["name"] == "android.hardware.sensors"]
    for service in init.get("sensor_services", []):
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
                        raise ValueError("Sensor library scan limit exceeded")
                    if LIB.fullmatch(entry.name):
                        names.append(entry.name)
                        if len(names) > MAX_FILES:
                            raise ValueError("Sensor candidate limit exceeded")
                for name in sorted(names):
                    if len(libraries) >= MAX_FILES:
                        raise ValueError("Sensor library limit exceeded")
                    guest = directory + "/" + name
                    libraries[guest] = None
                    try:
                        path = guest_path(root, guest)
                        size = path.lstat().st_size
                        if total + size > MAX_BYTES:
                            raise ValueError("Sensor ELF aggregate budget exceeded")
                        raw = read_regular(path, 64 * 1024 * 1024)
                        total += len(raw)
                        info = inspect_elf(raw)
                        if info["abi"] != abi or info["elf_type"] != "ET_DYN" or not info["has_dynamic"]:
                            raise ValueError("Sensor library ELF ABI or type mismatch")
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
    iio = iio_inventory(root, errors)
    try:
        for i, entry in enumerate(guest_path(root, "/dev").iterdir()):
            if i >= MAX_SCAN:
                raise ValueError("Sensor device scan limit exceeded")
            if re.fullmatch(r"(?:iio:device[0-9]+|ssp_sensorhub|sensorhub|sensors)", entry.name):
                guest = "/dev/" + entry.name
                nodes[guest] = stat.S_ISCHR(guest_path(root, guest).lstat().st_mode)
                if not nodes[guest]:
                    errors.append(guest + ": not a character device")
    except FileNotFoundError:
        pass
    except (OSError, ValueError) as exc:
        errors.append(str(exc))
    candidates = {k for item in dt if item["enabled"] for k in item["kinds"]}
    return {"status": "STATIC_SENSOR_INVENTORY_ONLY" if not errors and declared and
            any(s["elf"] for s in services) and any(libraries.values()) and candidates
            else "REVIEW_REQUIRED",
            "hal_declarations": declared, "services": services, "libraries": libraries,
            "dt_candidates": dt, "enabled_dt_sensor_kinds": sorted(candidates),
            "iio_snapshot": iio, "device_nodes": nodes,
            "kernel_config": None if kernel_config is None else {k: kernel_config.get(k) for k in KERNEL_KEYS},
            "errors": errors, "hal_registered": False, "sensor_events_verified": False,
            "heart_rate_verified": False, "calibration_verified": False, "safe_to_flash": False}
