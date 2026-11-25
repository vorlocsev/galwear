#!/usr/bin/env python3
"""Offline dex2oat and Zygote launch prerequisites; never starts guest processes."""
from __future__ import annotations

from r800_android_userspace_preflight import elf_check, guest_path, read_regular

MAX_PROP = 1024 * 1024
PROP_FILES = ("/default.prop", "/system/build.prop", "/vendor/build.prop",
              "/system/etc/prop.default", "/product/build.prop", "/system_ext/build.prop")
ZYGOTE_ABIS = {"zygote32": ("arm",), "zygote64": ("arm64",),
               "zygote32_64": ("arm", "arm64"), "zygote64_32": ("arm64", "arm")}
DEX2OAT_DIRS = ("/apex/com.android.art/bin", "/apex/com.android.runtime/bin", "/system/bin")
DEX2OAT_NAMES = ("dex2oat", "dex2oat32", "dex2oat64")


def property_inventory(root):
    values, errors = {}, []
    for path in PROP_FILES:
        try:
            text = read_regular(guest_path(root, path), MAX_PROP).decode("utf-8")
        except FileNotFoundError:
            continue
        except (OSError, ValueError) as exc:
            errors.append(path + ": " + str(exc))
            continue
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            name, value = (p.strip() for p in line.split("=", 1))
            if name == "ro.zygote" or name.startswith(("dalvik.vm.", "ro.product.cpu.abi")):
                values.setdefault(name, []).append({"source": path, "value": value})
                if sum(len(v) for v in values.values()) > 1024:
                    errors.append("ART property inventory limit exceeded")
                    return values, errors
    return values, errors


def executable(root, path):
    if not path.startswith("/") or ".." in path.split("/") or any(ch in path for ch in "$*?{}[]"):
        raise ValueError("Unresolved guest executable")
    info = elf_check(root, path)
    if info["interpreter"]:
        interp = elf_check(root, info["interpreter"])
        if interp["architecture"] != info["architecture"] or interp["interpreter"]:
            raise ValueError("Incompatible guest interpreter")
    return info


def audit(root, init, precompiled):
    properties, errors = property_inventory(root)
    declared = sorted({v["value"] for v in properties.get("ro.zygote", [])})
    mode = declared[0] if len(declared) == 1 and declared[0] in ZYGOTE_ABIS else None
    if mode is None:
        errors.append("Unresolved or unsupported ro.zygote")
    expected = ZYGOTE_ABIS.get(mode, ())
    compilers, services = {}, {}
    for directory in DEX2OAT_DIRS:
        for name in DEX2OAT_NAMES:
            path = directory + "/" + name
            try:
                guest_path(root, path)
            except FileNotFoundError:
                continue
            except (OSError, ValueError) as exc:
                errors.append(path + ": " + str(exc))
                continue
            try:
                compilers[path] = executable(root, path)
                abi = compilers[path]["architecture"]
                if (name.endswith("32") and abi != "arm" or
                        name.endswith("64") and abi != "arm64"):
                    raise ValueError("dex2oat filename and ELF ABI disagree")
            except (OSError, ValueError) as exc:
                compilers[path] = None
                errors.append(path + ": " + str(exc))
    if not any(compilers.values()):
        errors.append("No inspected dex2oat executable")
    for service in init["services"]:
        name = service["name"]
        if name not in ("zygote", "zygote_secondary"):
            continue
        if name in services:
            errors.append("Ambiguous Zygote service: " + name)
            continue
        path = service["executable"]
        item = {"path": path, "source": service["source"], "elf": None,
                "zygote_arg": "--zygote" in service["args"],
                "system_server_arg": "--start-system-server" in service["args"]}
        services[name] = item
        try:
            item["elf"] = executable(root, path)
            if not item["zygote_arg"]:
                errors.append(name + ": --zygote missing")
            if name == "zygote" and not item["system_server_arg"]:
                errors.append(name + ": system-server argument missing")
            if name == "zygote_secondary" and item["system_server_arg"]:
                errors.append(name + ": unexpected system-server argument")
        except (OSError, ValueError) as exc:
            errors.append(name + ": " + str(exc))
    required = ("zygote", "zygote_secondary") if len(expected) == 2 else ("zygote",)
    for index, name in enumerate(required):
        item = services.get(name)
        if item is None or item["elf"] is None:
            errors.append("Missing inspected service: " + name)
        elif expected and item["elf"]["architecture"] != expected[index]:
            errors.append(name + ": ro.zygote ABI mismatch")
    if len(expected) == 1 and "zygote_secondary" in services:
        errors.append("Secondary Zygote with single-ABI mode")
    images = {abi: [path for path, group in precompiled["groups"].items()
                    if group["isa"] == abi and group["boot_image"] and
                    group["companion_headers_present"]] for abi in expected}
    missing_images = [abi for abi, paths in images.items() if not paths]
    return {"status": "STATIC_LAUNCH_INVENTORY_ONLY" if not errors and not missing_images else "REVIEW_REQUIRED",
            "properties": properties, "zygote_mode": mode, "expected_abis": list(expected),
            "dex2oat": compilers, "zygote_services": services, "boot_image_candidates": images,
            "missing_boot_image_candidates": missing_images, "errors": errors,
            "property_precedence_verified": False, "dex2oat_executed": False,
            "boot_image_compatibility_verified": False, "zygote_started": False,
            "system_server_started": False, "safe_to_flash": False}
