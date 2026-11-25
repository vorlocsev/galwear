#!/usr/bin/env python3
"""Inventory original Android init and experimental service/client outputs.

This is a static ELF inventory, not a dependency closure or runtime test.
"""
import argparse
import json
from pathlib import Path
import subprocess

from r800_android_dynamic_audit import inspect_elf

MODULES = {
    "init_second_stage": "init",
    "galwear_property_service": "galwear_property_service",
    "galwear_property_client": "galwear_property_client",
}
INTERPRETERS = {"/system/bin/linker64", "/system/bin/bootstrap/linker64"}


def find_binary(root, name):
    paths = [root / "system/bin" / name, root / "system/bin/bootstrap" / name]
    files = [p for p in paths if p.is_file() and not p.is_symlink()]
    if len(files) != 1 or files[0].resolve() != files[0].absolute():
        raise ValueError("Missing, ambiguous or symlinked build output: " + name)
    return files[0]


def inventory(root, readelf):
    root = root.resolve(strict=True)
    modules = {}
    for module, name in MODULES.items():
        path = find_binary(root, name)
        info = inspect_elf(path, readelf)
        if info["elf_type"] != 3 or info["interpreter"] not in INTERPRETERS:
            raise ValueError("Unexpected Android dynamic executable: " + module)
        if "libc.so" not in info["needed"]:
            raise ValueError("Missing direct Bionic dependency: " + module)
        modules[module] = {**info, "path": str(path.relative_to(root))}
    return {
        "status": "ORIGINAL_INIT_ELF_INVENTORY_ONLY",
        "modules": modules,
        "direct_dependencies": sorted({lib for info in modules.values() for lib in info["needed"]}),
        "dependency_closure_verified": False,
        "android_init_started": False,
        "property_service_started": False,
        "socket_transaction_tested": False,
        "android_sepolicy_tested": False,
        "safe_to_flash": False,
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--product-out", required=True, type=Path)
    p.add_argument("--report", required=True, type=Path)
    p.add_argument("--readelf", default="readelf")
    a = p.parse_args()
    try:
        report = inventory(a.product_out, a.readelf)
        rc = 0
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        report = {"status": "REJECT", "reason": str(exc), "safe_to_flash": False}
        rc = 2
    a.report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(report["status"])
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
