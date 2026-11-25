#!/usr/bin/env python3
"""Generate a disposable non-release DTB without historical external initrd pointers."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

from r800_dtb_memory_audit import inspect, DTB_SIZE

EXPECTED = {"linux,initrd-start": 0x84000000, "linux,initrd-end": 0x841fffff}
CHOSEN = re.compile(r"(?m)^([ \t]*)chosen\s*\{([^{}]*)^\1\};")
PROPERTY = re.compile(r"(?m)^[ \t]*(linux,initrd-start|linux,initrd-end)\s*=\s*<\s*(0x[0-9a-fA-F]+|[0-9]+)\s*>;[ \t]*\n")


def remove_external_initrd(source: str) -> str:
    matches = list(CHOSEN.finditer(source))
    if len(matches) != 1:
        raise ValueError("Expected exactly one simple chosen node")
    node = matches[0]
    props = list(PROPERTY.finditer(node.group(2)))
    if len(props) != 2 or {p[1]: int(p[2], 0) for p in props} != EXPECTED:
        raise ValueError("Unexpected historical external initrd properties")
    body = PROPERTY.sub("", node.group(2))
    if re.search(r"linux,initrd-(start|end)", body):
        raise ValueError("Duplicate or unsupported initrd property")
    result = source[:node.start(2)] + body + source[node.end(2):]
    if re.search(r"linux,initrd-(start|end)", result):
        raise ValueError("External initrd property outside chosen")
    return result


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def dtc(*args: str) -> None:
    subprocess.run(["dtc", *args], check=True, timeout=60)


def generate(source: Path, out: Path) -> dict:
    if source.is_symlink() or not source.is_file():
        raise ValueError("Expected regular DTS input")
    raw = source.read_bytes()
    if not 0 < len(raw) <= 1024 * 1024:
        raise ValueError("DTS size outside audit bounds")
    derived = remove_external_initrd(raw.decode("utf-8"))
    out.mkdir(parents=False, exist_ok=False)
    original = out / "original.dtb"
    experimental = out / "embedded-only.dtb"
    dts = out / "embedded-only.dts"
    dts.write_text(derived, encoding="utf-8")
    for src, dest in ((source, original), (dts, experimental)):
        dtc("-I", "dts", "-O", "dtb", "-S", str(DTB_SIZE), "-o", str(dest), str(src))
    before, after = inspect(original), inspect(experimental)
    if not before["external_initrd"] or after["external_initrd"] is not None:
        raise ValueError("External initrd delta not verified in compiled DTB")
    for key in ("ram_banks", "fixed_reserved", "dynamic_reserved"):
        if before[key] != after[key]:
            raise ValueError("Memory layout changed: " + key)
    # Compare canonical decompiled trees, not only selected memory properties.
    # Sorting normalizes property/node order; no other property may change.
    left, right = out / "original.canonical.dts", out / "derived.canonical.dts"
    for src, dest in ((original, left), (experimental, right)):
        dtc("-I", "dtb", "-O", "dts", "-s", "-o", str(dest), str(src))
    if remove_external_initrd(left.read_text()) != right.read_text():
        raise ValueError("Compiled DTB changed beyond the two initrd properties")
    if source.read_bytes() != raw:
        raise ValueError("Original DTS changed during derivation")
    report = {
        "schema": "galwear-r800-embedded-dtb-v1",
        "status": "STATIC_TWO_PROPERTY_DELTA_ONLY",
        "source_sha256": hashlib.sha256(raw).hexdigest(),
        "original_dtb_sha256": digest(original),
        "derived_dtb_sha256": digest(experimental),
        "removed_properties": sorted(EXPECTED),
        "all_other_canonical_properties_equal": True,
        "bootargs_unchanged": True,
        "boot_blockers": after["boot_blockers"] + [
            "SBOOT_MAY_REINSERT_EXTERNAL_INITRD",
            "EFFECTIVE_BOOTARGS_AND_KERNEL_DRIVER_SIDE_EFFECTS_UNVERIFIED",
        ],
        "device_contacted": False,
        "boot_tested": False,
        "safe_to_flash": False,
    }
    (out / "embedded-dtb-evidence.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--source", required=True, type=Path)
    p.add_argument("--out-dir", required=True, type=Path)
    a = p.parse_args()
    try:
        report = generate(a.source, a.out_dir)
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        print("REJECT:", exc)
        return 2
    print(report["status"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
