#!/usr/bin/env python3
"""Offline graphics candidate inventory; does not initialize EGL or access devices."""
from __future__ import annotations
import hashlib
import re
import stat

from r800_android_userspace_preflight import guest_path, read_regular
from r800_art_launch import executable

MAX_ELF = 64 * 1024 * 1024
MAX_SCAN = 8192
MAX_LIBRARIES = 128
MAX_LIBRARY_BYTES = 256 * 1024 * 1024
HALS = ("composer", "allocator", "mapper")
PARTITIONS = ("system", "vendor", "odm", "system_ext", "product")
LIB_PATTERN = re.compile(r"(?:lib(?:EGL|GLESv1_CM|GLESv2|GLES|Mali|mali|gralloc|hwcomposer)(?:[._-][A-Za-z0-9_.-]+)?|(?:gralloc|hwcomposer)\.[A-Za-z0-9_.-]+|android\.hardware\.graphics\.(?:composer|allocator|mapper)@[0-9.]+(?:-impl)?)\.so")
DEVICES = ("/dev/mali0", "/dev/mali", "/dev/graphics/fb0", "/dev/dri/card0",
           "/dev/dri/renderD128")
KERNEL_KEYS = ("CONFIG_DRM", "CONFIG_FB", "CONFIG_DRM_EXYNOS", "CONFIG_MALI_MIDGARD",
               "CONFIG_MALI_BIFROST", "CONFIG_MALI_KBASE", "CONFIG_SYNC_FILE",
               "CONFIG_DMA_SHARED_BUFFER", "CONFIG_ION", "CONFIG_DMABUF_HEAPS")


def audit(root, init, vintf, inspect_elf, kernel_config=None):
    errors, services, libraries, nodes = [], [], {}, {}
    declared = {kind: [] for kind in HALS}
    for doc in vintf["files"].values():
        if doc["kind"] != "manifest" or doc["type"] != "device":
            continue
        for entry in doc["entries"]:
            for kind in HALS:
                if entry["name"] == "android.hardware.graphics." + kind:
                    declared[kind].append(entry)
    for service in init.get("graphics_services", []):
        item = {"name": service["name"], "path": service["executable"],
                "source": service["source"], "elf": None,
                "interfaces": [o["args"] for o in service["options"] if o["name"] == "interface"]}
        services.append(item)
        try:
            item["elf"] = executable(root, item["path"])
        except (OSError, ValueError) as exc:
            errors.append(item["name"] + ": " + str(exc))
    sf = [s for s in services if s["name"] == "surfaceflinger"]
    if len(sf) != 1 or not sf[0]["elf"]:
        errors.append("Missing or ambiguous inspected SurfaceFlinger service")
    scanned = total = 0
    exhausted = False
    for part in PARTITIONS:
        if exhausted:
            break
        for abi, lib in (("arm", "lib"), ("arm64", "lib64")):
            if exhausted:
                break
            for sub in ("", "/egl", "/hw"):
                directory = "/" + part + "/" + lib + sub
                try:
                    path = guest_path(root, directory)
                    names = []
                    for entry in path.iterdir():
                        scanned += 1
                        if scanned > MAX_SCAN:
                            raise ValueError("Graphics directory scan limit exceeded")
                        if LIB_PATTERN.fullmatch(entry.name):
                            names.append(entry.name)
                            if len(names) > MAX_LIBRARIES:
                                raise ValueError("Graphics directory candidate limit exceeded")
                    for name in sorted(names):
                        if len(libraries) >= MAX_LIBRARIES:
                            raise ValueError("Graphics library count limit exceeded")
                        guest = directory + "/" + name
                        libraries[guest] = None
                        try:
                            resolved = guest_path(root, guest)
                            length = resolved.lstat().st_size
                            if length > MAX_ELF or total + length > MAX_LIBRARY_BYTES:
                                raise ValueError("Graphics ELF byte budget exceeded")
                            data = read_regular(resolved, MAX_ELF)
                            total += len(data)
                            info = inspect_elf(data)
                            if (info["abi"] != abi or info["elf_type"] != "ET_DYN" or
                                    not info["has_dynamic"]):
                                raise ValueError("Graphics library is not compatible dynamic ELF")
                            libraries[guest] = {"abi": abi, "soname": info["soname"],
                                                "sha256": hashlib.sha256(data).hexdigest(),
                                                "bytes": len(data), "needed": info["needed"],
                                                "version_needs": info["version_needs"],
                                                "version_definitions": info["version_definitions"],
                                                "dynamic_symbol_count": info["dynamic_symbol_count"],
                                                "custom_search_path": info["custom_search_path"]}
                        except (OSError, ValueError) as exc:
                            errors.append(guest + ": " + str(exc))
                            if "budget exceeded" in str(exc):
                                exhausted = True
                                break
                except FileNotFoundError:
                    continue
                except (OSError, ValueError) as exc:
                    errors.append(directory + ": " + str(exc))
                    if "limit exceeded" in str(exc):
                        exhausted = True
                if exhausted:
                    break
    for name in DEVICES:
        try:
            nodes[name] = stat.S_ISCHR(guest_path(root, name).lstat().st_mode)
            if not nodes[name]:
                errors.append(name + ": not a character device")
        except FileNotFoundError:
            nodes[name] = False
        except (OSError, ValueError) as exc:
            nodes[name] = False
            errors.append(name + ": " + str(exc))
    candidates = {abi: {"egl": [], "gles2": [], "mali": [], "legacy_hal": []}
                  for abi in ("arm", "arm64")}
    for path, info in libraries.items():
        if not info:
            continue
        name = path.rsplit("/", 1)[1]
        items = candidates[info["abi"]]
        if name.startswith("libEGL"):
            items["egl"].append(path)
        if name.startswith("libGLESv2"):
            items["gles2"].append(path)
        if name.lower().startswith("libmali"):
            items["mali"].append(path)
        if name.startswith(("gralloc.", "hwcomposer.")):
            items["legacy_hal"].append(path)
    sf_abi = sf[0]["elf"]["architecture"] if len(sf) == 1 and sf[0]["elf"] else None
    missing = [kind for kind in HALS if not declared[kind]]
    if sf_abi and not all(candidates[sf_abi][kind] for kind in ("egl", "gles2")):
        errors.append("SurfaceFlinger ABI has incomplete EGL/GLES candidate inventory")
    return {"status": "STATIC_GRAPHICS_INVENTORY_ONLY" if not errors and not missing else "REVIEW_REQUIRED",
            "surfaceflinger_abi": sf_abi, "services": services, "declared_hals": declared,
            "missing_hal_declarations": missing, "libraries": libraries, "candidates": candidates,
            "device_nodes": nodes, "kernel_config": None if kernel_config is None else
            {key: kernel_config.get(key) for key in KERNEL_KEYS},
            "errors": errors, "egl_initialized": False, "gpu_driver_compatible": False,
            "hal_registration_verified": False, "surfaceflinger_started": False,
            "display_output_verified": False, "safe_to_flash": False}
