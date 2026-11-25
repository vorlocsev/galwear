#!/usr/bin/env python3
"""Read-only SM-R800 DTB identity and physical memory audit; no boot image."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess

DTB_SIZE = 133120  # Historical NZIT template slot, not a retail validation.
SCHEMA = "galwear-r800-dtb-memory-v1"


class AuditError(ValueError):
    pass


def get(dtb: Path, *args: str) -> str:
    result = subprocess.run(["fdtget", *args[:1], str(dtb), *args[1:]],
                            capture_output=True, text=True, timeout=10)
    if result.returncode:
        raise AuditError("fdtget failed: " + " ".join(args))
    return result.stdout.strip()


def cells(dtb: Path, node: str, prop: str) -> list[int]:
    result = subprocess.run(["fdtget", "-t", "x", str(dtb), node, prop],
                            capture_output=True, text=True, timeout=10)
    if result.returncode:
        raise AuditError(f"Missing or invalid {node}:{prop}")
    values = [int(x, 16) for x in result.stdout.split()]
    if any(not 0 <= x <= 0xffffffff for x in values):
        raise AuditError("Invalid 32-bit cell")
    return values


def strings(dtb: Path, node: str, prop: str) -> str:
    result = subprocess.run(["fdtget", "-t", "s", str(dtb), node, prop],
                            capture_output=True, text=True, timeout=10)
    if result.returncode:
        raise AuditError(f"Missing string {node}:{prop}")
    return result.stdout.strip()


def ranges(values: list[int], label: str) -> list[dict]:
    if not values or len(values) % 3:
        raise AuditError(f"Malformed reg cells: {label}")
    result = []
    for high, low, size in zip(values[::3], values[1::3], values[2::3]):
        start = (high << 32) | low
        if size == 0 or start + size > 1 << 64:
            raise AuditError(f"Invalid range: {label}")
        result.append({"node": label, "start": start, "end_exclusive": start + size,
                       "size_bytes": size})
    return result


def validate_disjoint(items: list[dict], label: str) -> None:
    ordered = sorted(items, key=lambda x: x["start"])
    for left, right in zip(ordered, ordered[1:]):
        if left["end_exclusive"] > right["start"]:
            raise AuditError(f"Overlapping {label}: {left['node']} and {right['node']}")


def contained(item: dict, ram: list[dict]) -> bool:
    return any(r["start"] <= item["start"] and item["end_exclusive"] <= r["end_exclusive"]
               for r in ram)


def inspect(dtb: Path) -> dict:
    if dtb.is_symlink() or not dtb.is_file() or dtb.stat().st_size != DTB_SIZE:
        raise AuditError("Expected regular DTB of exactly 133120 bytes")
    data = dtb.read_bytes()
    magic, total = struct.unpack_from(">II", data)
    if magic != 0xd00dfeed or total != len(data):
        raise AuditError("Invalid FDT magic or totalsize")
    if strings(dtb, "/", "model") != "GALILEO-LARGE-BT":
        raise AuditError("Unexpected SM-R800 model")
    if "samsung,exynos9110" not in strings(dtb, "/", "compatible").split():
        raise AuditError("Unexpected SoC compatible")
    for node in ("/", "/reserved-memory"):
        if cells(dtb, node, "#address-cells") != [2] or cells(dtb, node, "#size-cells") != [1]:
            raise AuditError(f"Unexpected memory cell layout: {node}")
    ram = []
    for child in get(dtb, "-l", "/").splitlines():
        if child == "memory" or child.startswith("memory@"):
            node = "/" + child
            if strings(dtb, node, "device_type") != "memory":
                raise AuditError("Invalid memory device_type")
            ram.extend(ranges(cells(dtb, node, "reg"), node))
    if not ram:
        raise AuditError("No RAM banks")
    validate_disjoint(ram, "RAM banks")
    fixed, dynamic = [], []
    for child in get(dtb, "-l", "/reserved-memory").splitlines():
        node = "/reserved-memory/" + child
        props = get(dtb, "-p", node).splitlines()
        if "status" in props and strings(dtb, node, "status") not in ("okay", "ok"):
            continue
        if "reg" in props:
            fixed.extend(ranges(cells(dtb, node, "reg"), node))
        elif "size" in props:
            size = cells(dtb, node, "size")
            if len(size) != 1 or size[0] == 0:
                raise AuditError(f"Invalid dynamic reserved size: {node}")
            dynamic.append({"node": node, "size_bytes": size[0],
                            "address_known": False})
        else:
            raise AuditError(f"Reserved node missing reg or size: {node}")
    validate_disjoint(fixed, "fixed reserved regions")
    blockers = []
    for item in fixed:
        if not contained(item, ram):
            blockers.append("FIXED_RESERVED_OUTSIDE_DECLARED_RAM:" + item["node"])
    chosen = get(dtb, "-p", "/chosen").splitlines()
    external = None
    if "linux,initrd-start" in chosen or "linux,initrd-end" in chosen:
        start = cells(dtb, "/chosen", "linux,initrd-start")
        end = cells(dtb, "/chosen", "linux,initrd-end")
        if len(start) != len(end) or len(start) not in (1, 2):
            raise AuditError("Malformed external initrd bounds")
        a = int.from_bytes(b"".join(x.to_bytes(4, "big") for x in start), "big")
        b = int.from_bytes(b"".join(x.to_bytes(4, "big") for x in end), "big")
        if b <= a:
            raise AuditError("Invalid external initrd range")
        external = {"start": a, "end_exclusive_as_declared": b}
        blockers.append("EXTERNAL_INITRD_PRESENT_IN_EMBEDDED_MODE_UNVERIFIED")
        if not contained({"start": a, "end_exclusive": b}, ram):
            blockers.append("EXTERNAL_INITRD_OUTSIDE_DECLARED_RAM")
        if any(a < r["end_exclusive"] and r["start"] < b for r in fixed):
            blockers.append("EXTERNAL_INITRD_OVERLAPS_FIXED_RESERVATION")
    blockers.append("RETAIL_SBOOT_LOAD_ADDRESSES_AND_DTB_SELECTION_UNVERIFIED")
    return {"schema": SCHEMA, "status": "STATIC_DTB_AUDIT_ONLY",
            "dtb_sha256": hashlib.sha256(data).hexdigest(),
            "dtb_bytes": len(data), "ram_banks": ram,
            "fixed_reserved": fixed, "dynamic_reserved": dynamic,
            "external_initrd": external, "boot_blockers": blockers,
            "boot_tested": False, "safe_to_flash": False}


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--dtb", required=True, type=Path)
    p.add_argument("--report", required=True, type=Path)
    args = p.parse_args()
    try:
        report = inspect(args.dtb)
        rc = 0
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        report = {"schema": SCHEMA, "status": "REJECT", "reason": str(exc),
                  "boot_tested": False, "safe_to_flash": False}
        rc = 2
    args.report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(report["status"])
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
