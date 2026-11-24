#!/usr/bin/env python3
"""Read-only Mali/EGL/graphics HAL inventory for an extracted R800 guest."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import struct

from r800_android_userspace_preflight import guest_path, read_regular, MAX_ELF
from r800_android_linker_audit import inspect, audit as linker_audit

REQUIRED = {
    "CONFIG_ARM64": "y", "CONFIG_COMPAT": "y", "CONFIG_MALI_T72X": "y",
    "CONFIG_MALI_R28P0": "y", "CONFIG_MALI_MIDGARD": "y",
    "CONFIG_MALI_PLATFORM_NAME": '"exynos"', "CONFIG_ION": "y",
    "CONFIG_ION_EXYNOS": "y", "CONFIG_DMA_SHARED_BUFFER": "y",
    "CONFIG_SYNC_FILE": "y", "CONFIG_FB": "y",
}
ROLES = {
    "egl_loader": ("/system/lib/libEGL.so",),
    "gles2_loader": ("/system/lib/libGLESv2.so",),
    "mali_monolithic": ("/vendor/lib/egl/libGLES_mali.so", "/vendor/lib/egl/libGLES.so"),
    "mali_egl": ("/vendor/lib/egl/libEGL_mali.so",),
    "mali_gles1": ("/vendor/lib/egl/libGLESv1_CM_mali.so",),
    "mali_gles2": ("/vendor/lib/egl/libGLESv2_mali.so",),
    "gralloc": ("/vendor/lib/hw/gralloc.exynos5.so",),
    "composer": ("/vendor/lib/hw/hwcomposer.r800.so",),
}
MANDATORY = ("egl_loader", "gles2_loader", "gralloc", "composer")


def config_inventory(path):
    raw = read_regular(path, 1024 * 1024)
    settings = {}
    for line in raw.decode("utf-8").splitlines():
        if line.startswith("CONFIG_") and "=" in line:
            key, val = line.split("=", 1)
        elif line.startswith("# CONFIG_") and line.endswith(" is not set"):
            key, val = line[2:-11], "n"
        else:
            continue
        if key in settings:
            raise ValueError("Duplicate kernel option " + key)
        settings[key] = val
    return {
        "sha256": hashlib.sha256(raw).hexdigest(),
        "missing_or_wrong": {k: {"expected": v, "actual": settings.get(k)}
                             for k, v in REQUIRED.items() if settings.get(k) != v},
        "mali_dma_fence": settings.get("CONFIG_MALI_DMA_FENCE"),
        "mali_dvfs": settings.get("CONFIG_MALI_DVFS"),
        "mali_sec_utilization": settings.get("CONFIG_MALI_SEC_UTILIZATION"),
    }


def library(root, path):
    data = read_regular(guest_path(root, path), MAX_ELF)
    info = inspect(data)
    if info["abi"] != "arm" or struct.unpack_from("<H", data, 16)[0] != 3:
        raise ValueError("Expected ARM32 ET_DYN library")
    if not info["has_dynamic"]:
        raise ValueError("Missing PT_DYNAMIC")
    return {**info, "sha256": hashlib.sha256(data).hexdigest()}


def audit(root, config):
    kernel = config_inventory(config)
    roles, errors, targets = {}, [], []
    for role, candidates in ROLES.items():
        found = {}
        for path in candidates:
            try:
                found[path] = library(root, path)
                targets.append(path)
            except FileNotFoundError:
                continue
            except (OSError, ValueError) as exc:
                errors.append({"path": path, "error": str(exc)})
        roles[role] = found
    missing = [r for r in MANDATORY if not roles[r]]
    # A single combined implementation or all three split Mali libraries.
    if not roles["mali_monolithic"] and not all(roles[x] for x in
            ("mali_egl", "mali_gles1", "mali_gles2")):
        missing.append("mali_driver_family")
    # Bound discovery to known candidate paths. No loading or executing ELF.
    deps = linker_audit(root, tuple(targets), extra_arm_dirs=("/vendor/lib/egl",)) if targets else None
    ok = not missing and not errors and not kernel["missing_or_wrong"] and deps is not None and deps["status"] == "CANDIDATES_FOUND_ONLY"
    return {
        "schema": "galwear-r800-graphics-inventory-v1",
        "status": "STATIC_GRAPHICS_CANDIDATES_FOUND" if ok else "REVIEW_REQUIRED",
        "kernel": kernel, "roles": roles, "missing_roles": missing, "errors": errors,
        "dependencies": deps,
        "donor_layout_candidates_only": True,
        "android_namespace_resolution_verified": False,
        "egl_symbols_verified": False, "mali_ioctl_abi_verified": False,
        "gpu_rendering_tested": False, "android_boot_tested": False,
        "safe_to_flash": False,
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--root", type=Path, required=True)
    p.add_argument("--config", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    if a.output.resolve().is_relative_to(a.root.resolve()):
        p.error("Report must be outside guest root")
    try:
        report = audit(a.root, a.config)
    except (OSError, ValueError) as exc:
        report = {"schema": "galwear-r800-graphics-inventory-v1",
                  "status": "REVIEW_REQUIRED", "errors": [str(exc)],
                  "safe_to_flash": False}
    a.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(report["status"])
    return 0 if report["status"] == "STATIC_GRAPHICS_CANDIDATES_FOUND" else 2


if __name__ == "__main__":
    raise SystemExit(main())
