#!/usr/bin/env python3
"""Read-only display evidence from a supplied flattened device tree."""
from __future__ import annotations
import struct
from r800_android_userspace_preflight import guest_path, read_regular

MAX_DTB = 4 * 1024 * 1024
KEYS = ("CONFIG_DRM", "CONFIG_DRM_EXYNOS", "CONFIG_DRM_MIPI_DSI",
        "CONFIG_DRM_PANEL", "CONFIG_FB", "CONFIG_FB_S3C", "CONFIG_FB_MIPI_DSIM",
        "CONFIG_BACKLIGHT_CLASS_DEVICE")
EXPECTED_MODE = (360, 360)


def parse_dtb(data):
    if not 40 <= len(data) <= MAX_DTB:
        raise ValueError("Invalid DTB size")
    magic, total, off, strings, reserve, ver, compatible, _, slen, length = struct.unpack_from(">10I", data)
    if (magic != 0xd00dfeed or ver != 17 or compatible > 17 or total > len(data)
            or total < 40 or off < 40 or off % 4 or strings < 40 or reserve < 40
            or reserve % 8 or reserve + 16 > total or off + length > total
            or strings + slen > total or length % 4
            or (off < strings + slen and strings < off + length)):
        raise ValueError("Invalid DTB header")
    # Validate termination and disjoint ranges of the memory reservation map.
    end_reserve = reserve
    for _ in range(4096):
        if end_reserve + 16 > total:
            raise ValueError("Unterminated DTB reservation map")
        address, size = struct.unpack_from(">QQ", data, end_reserve)
        end_reserve += 16
        if not address and not size:
            break
    else:
        raise ValueError("DTB reservation limit exceeded")
    if any(reserve < end and start < end_reserve for start, end in
           ((off, off + length), (strings, strings + slen))):
        raise ValueError("Overlapping DTB blocks")
    table = data[strings:strings+slen]
    end = off + length
    pos, stack, nodes = off, [], {}
    records = 0
    while pos + 4 <= end:
        token = struct.unpack_from(">I", data, pos)[0]
        pos += 4
        records += 1
        if records > 65536:
            raise ValueError("DTB token limit exceeded")
        if token == 1:
            stop = data.find(b"\0", pos, end)
            if stop < 0 or stop - pos > 255 or len(stack) >= 64 or len(nodes) >= 4096:
                raise ValueError("Invalid DTB node")
            name = data[pos:stop].decode("ascii")
            pos = (stop + 4) & ~3
            if (not stack and (name or nodes)) or (stack and (not name or "/" in name or name in (".", ".."))):
                raise ValueError("Invalid DTB node name")
            path = (stack[-1].rstrip("/") + "/" + name) if stack else "/"
            if path in nodes:
                raise ValueError("Duplicate DTB node")
            nodes[path] = {}
            stack.append(path)
        elif token == 2:
            if not stack:
                raise ValueError("Unbalanced DTB node")
            stack.pop()
        elif token == 3:
            if not stack or pos + 8 > end:
                raise ValueError("Invalid DTB property header")
            n, keyoff = struct.unpack_from(">II", data, pos)
            pos += 8
            stop = table.find(b"\0", keyoff)
            if stop < 0 or stop == keyoff or stop - keyoff > 255 or pos + n > end:
                raise ValueError("Invalid DTB property bounds")
            key = table[keyoff:stop].decode("ascii")
            props = nodes[stack[-1]]
            if key in props:
                raise ValueError("Duplicate DTB property")
            props[key] = data[pos:pos+n]
            pos = (pos + n + 3) & ~3
        elif token == 4:
            continue
        elif token == 9:
            if stack or "/" not in nodes or pos != end:
                raise ValueError("Incomplete DTB structure")
            return nodes
        else:
            raise ValueError("Unknown DTB token")
    raise ValueError("DTB END token missing")


def strings(value):
    if not value:
        return []
    if not value.endswith(b"\0"):
        raise ValueError("Invalid DTB string property")
    return [v.decode("ascii") for v in value[:-1].split(b"\0")]


def cells(value):
    if len(value) not in (4, 12):
        raise ValueError("Unsupported display timing property")
    numbers = struct.unpack(">" + "I" * (len(value)//4), value)
    if len(numbers) == 3 and not numbers[0] <= numbers[1] <= numbers[2]:
        raise ValueError("Invalid display timing range")
    return numbers[1] if len(numbers) == 3 else numbers[0]


def inventory(nodes):
    candidates, timings = [], []
    enabled = {}
    for path, props in nodes.items():
        parent = path.rsplit("/", 1)[0] or "/"
        status = strings(props.get("status", b""))
        active = (not status or status == ["okay"] or status == ["ok"])
        enabled[path] = active and (path == "/" or enabled.get(parent, False))
        compatible = strings(props.get("compatible", b""))
        label = path.rsplit("/", 1)[-1].split("@", 1)[0]
        evidence = " ".join([label] + compatible).lower()
        if any(k in evidence for k in ("display", "panel", "dsi", "dsim", "decon", "fimd", "framebuffer")):
            candidates.append({"path": path, "compatible": compatible, "enabled": enabled[path]})
        if "hactive" in props and "vactive" in props:
            mode = [cells(props["hactive"]), cells(props["vactive"])]
            timing = {"path": path, "mode": mode, "enabled": enabled[path],
                      "expected_resolution": mode == list(EXPECTED_MODE)}
            if "clock-frequency" in props:
                timing["pixel_clock_hz"] = cells(props["clock-frequency"])
            timings.append(timing)
    return {"candidates": candidates, "timings": timings,
            "matching_enabled_timing": any(t["enabled"] and t["expected_resolution"] for t in timings)}


def audit(root, kernel_config=None, dtb=None):
    errors, evidence = [], None
    if dtb is not None:
        try:
            evidence = inventory(parse_dtb(dtb))
        except (ValueError, UnicodeError) as exc:
            errors.append(str(exc))
    else:
        errors.append("Target DTB not supplied")
    sysfs = {}
    for name in ("/sys/class/graphics/fb0/virtual_size", "/sys/class/graphics/fb0/modes",
                 "/sys/class/drm/card0-DSI-1/modes", "/sys/class/drm/card0-DSI-1/status"):
        try:
            sysfs[name] = read_regular(guest_path(root, name), 4096).decode("ascii").strip()
        except FileNotFoundError:
            continue
        except (OSError, ValueError) as exc:
            errors.append(name + ": " + str(exc))
    return {"status": "DISPLAY_DT_INVENTORY_ONLY" if evidence and
            evidence["matching_enabled_timing"] and not errors else "REVIEW_REQUIRED",
            "expected_mode": list(EXPECTED_MODE), "device_tree": evidence,
            "kernel_config": None if kernel_config is None else {k: kernel_config.get(k) for k in KEYS},
            "sysfs_snapshot": sysfs, "errors": errors,
            "panel_driver_verified": False, "dsi_link_verified": False,
            "display_output_verified": False, "safe_to_flash": False}
