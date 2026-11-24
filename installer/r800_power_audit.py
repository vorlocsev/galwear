#!/usr/bin/env python3
"""Read-only SM-R800 suspend/CPU-idle observations.

No device-control calls, sockets, subprocesses, root escalation, sysfs writes,
suspend requests or watchdog actions. A --root fixture path is supported for
all CI tests. Results are *observations*, never proof of sleep stability.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys
import time

SCHEMA = "galwear-r800-power-snapshot-v1"
MAX_FILE_BYTES = 8192

# Only read preselected low-risk numeric fields; never capture raw logs,
# MAC addresses, serial numbers, /proc/cmdline, or identifiable kernel text.
NUMERIC_PATHS = {
    "uptime_seconds": "proc/uptime",
    "wakeup_count": "sys/power/wakeup_count",
    "cpu0_state1_disable": "sys/devices/system/cpu/cpu0/cpuidle/state1/disable",
    "cpu0_state1_usage": "sys/devices/system/cpu/cpu0/cpuidle/state1/usage",
    "cpu0_state1_time": "sys/devices/system/cpu/cpu0/cpuidle/state1/time",
    "cpu1_state1_disable": "sys/devices/system/cpu/cpu1/cpuidle/state1/disable",
    "cpu1_state1_usage": "sys/devices/system/cpu/cpu1/cpuidle/state1/usage",
    "cpu1_state1_time": "sys/devices/system/cpu/cpu1/cpuidle/state1/time",
    "pd_off_mask": "sys/module/exynos_pd/parameters/r800_sleep_pd_off",
    "pd_dispaud_sleep_off": "sys/module/exynos_pd/parameters/r800_dispaud_sleep_off",
    "abox_runtime_poweroff": "sys/module/abox/parameters/r800_rtpm_poweroff",
    "battery_capacity_percent": "sys/class/power_supply/battery/capacity",
    "battery_temp_raw": "sys/class/power_supply/battery/temp",
    "battery_voltage_uv": "sys/class/power_supply/battery/voltage_now",
    "battery_current_ua": "sys/class/power_supply/battery/current_now",
}
SUSPEND_STATS = (
    "success", "fail", "failed_freeze", "failed_prepare", "failed_suspend",
    "failed_suspend_late", "failed_suspend_noirq", "failed_resume",
    "failed_resume_early", "failed_resume_noirq",
)
COUNTERS = {
    "wakeup_count", "cpu0_state1_usage", "cpu1_state1_usage",
    "cpu0_state1_time", "cpu1_state1_time",
}
STATUS_WHITELIST = {"Charging", "Discharging", "Full", "Not charging", "Unknown"}


def _in_root(root: Path, relative: str) -> Path | None:
    """Disallow path escapes even when a fixture contains malicious symlinks."""
    base = root.resolve(strict=True)
    candidate = root / relative
    try:
        resolved = candidate.resolve(strict=True)
    except (OSError, RuntimeError):
        return None
    try:
        resolved.relative_to(base)
    except ValueError:
        return None
    return resolved if resolved.is_file() else None


def _limited_read(root: Path, relative: str) -> str | None:
    p = _in_root(root, relative)
    if p is None:
        return None
    try:
        with p.open("r", encoding="utf-8", errors="replace") as fh:
            return fh.read(MAX_FILE_BYTES)
    except (OSError, ValueError):
        return None


def _numeric(text: str | None, *, uptime=False) -> int | float | None:
    if text is None:
        return None
    item = text.split()[0] if text.split() else ""
    if uptime:
        if not re.fullmatch(r"\d+(?:\.\d+)?", item):
            return None
        return float(item)
    if not re.fullmatch(r"-?(?:0[xX][0-9a-fA-F]+|\d+)", item):
        return None
    try:
        return int(item, 0) if item.lower().startswith("0x") else int(item, 10)
    except ValueError:
        return None


def _suspend_stats(root: Path) -> dict[str, int] | None:
    text = _limited_read(root, "sys/kernel/debug/suspend_stats")
    if text is None:
        return None
    result: dict[str, int] = {}
    for label, value in re.findall(r"(?m)^\s*([a-z_]+)\s*:\s*(\d+)\s*$", text):
        if label in SUSPEND_STATS:
            result[label] = int(value)
    return result if result else None


def snapshot(root: Path) -> dict:
    """Collect whitelisted metrics only, silently marking unavailable fields."""
    root = root.resolve(strict=True)
    values = {}
    unavailable = []
    for name, relative in NUMERIC_PATHS.items():
        value = _numeric(
            _limited_read(root, relative), uptime=name == "uptime_seconds")
        if value is None:
            unavailable.append(name)
        else:
            values[name] = value
    stats = _suspend_stats(root)
    if stats is None:
        unavailable.append("suspend_stats")
    status = _limited_read(root, "sys/class/power_supply/battery/status")
    charging = status.strip() if status else ""
    if charging not in STATUS_WHITELIST:
        charging = None
        unavailable.append("battery_status")
    wake = _limited_read(root, "sys/power/wake_lock")
    # Return existence of ONLY our own named lock, never other lock names.
    lock = bool(re.search(r"(?<!\w)r800helper(?!\w)", wake)) if wake is not None else None
    if lock is None:
        unavailable.append("r800helper_lock")
    return {
        "schema": SCHEMA,
        "captured_unix_seconds": int(time.time()),
        "power_modes": {
            "sleep_opt_in": _in_root(root, "oem/r800dev/android/SLEEP") is not None,
            "cpuidle_deep_opt_in": _in_root(root, "oem/r800dev/android/CPUIDLE_DEEP") is not None,
            "r800helper_lock_seen": lock,
        },
        "metrics": values,
        "suspend_stats": stats or {},
        "battery_status": charging,
        "unavailable": sorted(unavailable),
        "writes_to_device": False,
        "suspend_performed": False,
        "hardware_stability_verified": False,
    }


def compare(before: dict, after: dict) -> dict:
    if before.get("schema") != SCHEMA or after.get("schema") != SCHEMA:
        raise ValueError("Incompatible snapshot schema")
    b = before.get("metrics", {})
    a = after.get("metrics", {})
    if not isinstance(a, dict) or not isinstance(b, dict):
        raise ValueError("Invalid metrics")
    rebooted = (
        a.get("uptime_seconds", -1) < b.get("uptime_seconds", -1)
        if "uptime_seconds" in a and "uptime_seconds" in b else None)
    changes = {}
    for k in sorted(COUNTERS):
        if k in a and k in b:
            if not isinstance(a[k], int) or not isinstance(b[k], int):
                raise ValueError(f"Noninteger counter: {k}")
            changes[k] = a[k] - b[k] if a[k] >= b[k] else None
    for k in SUSPEND_STATS:
        bv = before.get("suspend_stats", {}).get(k)
        av = after.get("suspend_stats", {}).get(k)
        if isinstance(bv, int) and isinstance(av, int):
            changes["suspend_" + k] = av - bv if av >= bv else None
    mode_changed = before.get("power_modes") != after.get("power_modes")
    notes = [
        "Counters and mode flags do not establish a causal reason for hangs.",
        "Kernel power and watchdog behavior remain unverified on actual SM-R800.",
    ]
    if rebooted:
        notes.append("Uptime decreased; counter deltas may not be comparable.")
        changes = {k: None for k in changes}
    if mode_changed:
        notes.append("Power modes/lock observations changed; avoid causal comparison.")
    return {
        "schema": "galwear-r800-power-comparison-v1",
        "reboot_detected": rebooted,
        "power_modes_changed": mode_changed,
        "deltas": changes,
        "notes": notes,
        "hardware_stability_verified": False,
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Read-only SM-R800 power audit")
    sub = parser.add_subparsers(dest="action", required=True)
    snap = sub.add_parser("snapshot")
    snap.add_argument("--root", type=Path, default=Path("/"))
    snap.add_argument("--output", type=Path, required=True)
    cmp = sub.add_parser("compare")
    cmp.add_argument("--before", type=Path, required=True)
    cmp.add_argument("--after", type=Path, required=True)
    cmp.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.action == "snapshot":
            report = snapshot(args.root)
        else:
            report = compare(
                json.loads(args.before.read_text(encoding="utf-8")),
                json.loads(args.after.read_text(encoding="utf-8")))
        args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n",
                               encoding="utf-8")
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        print(f"[FAIL] {exc}", file=sys.stderr)
        return 2
    print(f"[PASS] {args.action}: read-only diagnostics, no hardware safety proof")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
