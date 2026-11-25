#!/usr/bin/env python3
"""Static Linux/Android input evidence for R800; never opens evdev devices."""
from __future__ import annotations
import re
import stat
import struct
from r800_android_userspace_preflight import guest_path, read_regular
from r800_display_inventory import parse_dtb, strings

MAX_FILES = 256
MAX_SCAN = 4096
MAX_CONFIG = 128 * 1024
MAX_TOTAL = 4 * 1024 * 1024
PARTITIONS = ("system", "vendor", "odm", "product", "system_ext")
KEYS = ("CONFIG_INPUT", "CONFIG_INPUT_EVDEV", "CONFIG_INPUT_TOUCHSCREEN",
        "CONFIG_TOUCHSCREEN", "CONFIG_KEYBOARD_GPIO", "CONFIG_INPUT_ROTARY_ENCODER",
        "CONFIG_INPUT_MISC")
KEY_NAME = re.compile(r"[A-Z][A-Z0-9_]{0,127}")
INTEREST = {"BACK", "HOME", "POWER", "WAKEUP", "STEM_PRIMARY",
            "STEM_1", "STEM_2", "STEM_3", "BUTTON_1", "BUTTON_2"}
AXES = {"WHEEL", "HSCROLL", "VSCROLL", "SCROLL"}


def dt_inventory(nodes):
    enabled, candidates = {}, []
    for path, props in nodes.items():
        parent = path.rsplit("/", 1)[0] or "/"
        status = strings(props.get("status", b""))
        enabled[path] = (not status or status in (["okay"], ["ok"])) and (
            path == "/" or enabled.get(parent, False))
        compatible = strings(props.get("compatible", b""))
        label = path.rsplit("/", 1)[-1].split("@", 1)[0]
        clue = " ".join([label] + compatible).lower()
        kinds = []
        if any(x in clue for x in ("touchscreen", "touch-screen", "touch", "tsp")):
            kinds.append("touchscreen")
        if any(x in clue for x in ("gpio-keys", "gpio_keys", "keypad")) or "linux,code" in props:
            kinds.append("keys")
        if any(x in clue for x in ("rotary", "bezel", "hall-wheel", "hall_wheel")):
            kinds.append("rotary")
        if not kinds:
            continue
        item = {"path": path, "compatible": compatible, "enabled": enabled[path], "kinds": kinds}
        for key in ("touchscreen-size-x", "touchscreen-size-y", "linux,code",
                    "rotary-encoder,steps", "rotary-encoder,steps-per-period", "linux,axis"):
            if key in props:
                if len(props[key]) != 4:
                    raise ValueError("Invalid input DT cell: " + key)
                item[key] = struct.unpack(">I", props[key])[0]
        candidates.append(item)
    return candidates


def number(value):
    if not re.fullmatch(r"(?:0[xX][0-9a-fA-F]{1,8}|[0-9]{1,10})", value):
        raise ValueError("Invalid keylayout numeric code")
    n = int(value, 16 if value.lower().startswith("0x") else 10)
    if n > 0xffffffff:
        raise ValueError("Keylayout code exceeds 32 bits")
    return n


def keylayout(text):
    keys, axes, review = [], [], []
    seen = set()
    for line in text.splitlines():
        words = line.split("#", 1)[0].split()
        if not words:
            continue
        if len(keys) + len(axes) + len(review) >= 4096:
            raise ValueError("Keylayout record limit exceeded")
        if words[0] == "key":
            usage = len(words) > 1 and words[1] == "usage"
            start = 2 if usage else 1
            if len(words) < start + 2 or not KEY_NAME.fullmatch(words[start+1]):
                raise ValueError("Invalid keylayout key record")
            code = number(words[start])
            ident = ("usage" if usage else "key", code)
            if ident in seen:
                raise ValueError("Duplicate keylayout code")
            seen.add(ident)
            keys.append({"code": code, "usage": usage, "name": words[start+1],
                         "flags": words[start+2:]})
        elif words[0] == "axis":
            if len(words) < 3:
                raise ValueError("Invalid keylayout axis record")
            code = number(words[1])
            ident = ("axis", code)
            if ident in seen:
                raise ValueError("Duplicate keylayout axis")
            seen.add(ident)
            axes.append({"code": code, "mapping": words[2:]})
        else:
            review.append(words[0])
    return {"keys": keys, "axes": axes, "uninspected": review}


def idc(text):
    props = {}
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        if "=" not in line:
            raise ValueError("Invalid IDC property")
        key, value = (v.strip() for v in line.split("=", 1))
        if not key or not value or key in props or len(props) >= 4096:
            raise ValueError("Invalid or duplicate IDC property")
        props[key] = value
    return props


def audit(root, kernel_config=None, dtb=None):
    errors, candidates, layouts, configs, nodes = [], [], {}, {}, {}
    if dtb is not None:
        try:
            candidates = dt_inventory(parse_dtb(dtb))
        except ValueError as exc:
            errors.append(str(exc))
    else:
        errors.append("Target DTB not supplied")
    scanned = total = 0
    for part in PARTITIONS:
        for folder, suffix, target, parser in (("keylayout", ".kl", layouts, keylayout),
                                               ("idc", ".idc", configs, idc)):
            directory = "/" + part + "/usr/" + folder
            try:
                names = []
                for entry in guest_path(root, directory).iterdir():
                    scanned += 1
                    if scanned > MAX_SCAN:
                        raise ValueError("Input directory scan limit exceeded")
                    if entry.name.endswith(suffix):
                        names.append(entry.name)
                        if len(names) > MAX_FILES:
                            raise ValueError("Input candidate limit exceeded")
                for name in sorted(names):
                    if len(layouts) + len(configs) >= MAX_FILES:
                        raise ValueError("Input file limit exceeded")
                    guest = directory + "/" + name
                    target[guest] = None
                    try:
                        raw = read_regular(guest_path(root, guest), MAX_CONFIG)
                        total += len(raw)
                        if total > MAX_TOTAL:
                            raise ValueError("Input aggregate byte limit exceeded")
                        target[guest] = parser(raw.decode("utf-8"))
                    except (OSError, ValueError) as exc:
                        errors.append(guest + ": " + str(exc))
                        if total > MAX_TOTAL:
                            break
            except FileNotFoundError:
                continue
            except (OSError, ValueError) as exc:
                errors.append(directory + ": " + str(exc))
    try:
        for index, entry in enumerate(guest_path(root, "/dev/input").iterdir()):
            if index >= MAX_SCAN:
                raise ValueError("Input node scan limit exceeded")
            if re.fullmatch(r"event[0-9]+", entry.name):
                path = "/dev/input/" + entry.name
                nodes[path] = stat.S_ISCHR(guest_path(root, path).lstat().st_mode)
                if not nodes[path]:
                    errors.append(path + ": not a character device")
    except FileNotFoundError:
        pass
    except (OSError, ValueError) as exc:
        errors.append(str(exc))
    mappings = [{"path": path, **k} for path, info in layouts.items() if info
                for k in info["keys"] if k["name"] in INTEREST]
    axis_mappings = [{"path": path, **a} for path, info in layouts.items() if info
                     for a in info["axes"] if AXES.intersection(a["mapping"])]
    kinds = {k for item in candidates if item["enabled"] for k in item["kinds"]}
    return {"status": "INPUT_STATIC_INVENTORY_ONLY" if not errors and
            {"touchscreen", "keys", "rotary"} <= kinds and layouts else "REVIEW_REQUIRED",
            "dt_candidates": candidates, "missing_dt_kinds": sorted(
                {"touchscreen", "keys", "rotary"} - kinds),
            "keylayouts": layouts, "idc": configs, "button_mappings": mappings,
            "rotary_axis_candidates": axis_mappings, "device_nodes": nodes,
            "kernel_config": None if kernel_config is None else {k: kernel_config.get(k) for k in KEYS},
            "errors": errors, "inputreader_verified": False, "touch_verified": False,
            "buttons_verified": False, "bezel_verified": False, "safe_to_flash": False}
