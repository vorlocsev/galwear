#!/usr/bin/env python3
"""Strict experimental SM-R800 NZIT candidate builder; not signature verification."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import struct

from r800_android_userspace_preflight import read_regular
from r800_display_inventory import parse_dtb, strings

PARTITION = 18874368
HEADER = 2048
SIG = 272
DT_OFFSET = 2048
DT_SIZE = 133120
MAX_TABLE = 4 * 1024 * 1024


def inspect_template(raw):
    if not HEADER + SIG <= len(raw) <= PARTITION:
        raise ValueError("Template size outside SM-R800 bounds")
    magic, align, ksize, total, dtsize, ramdisk, hdrsize = struct.unpack_from("<7I", raw)
    if (magic != 0x54495a4e or hdrsize != HEADER or align != 0x8000 or
            not ksize or total != ksize + align or not 12 <= dtsize <= MAX_TABLE):
        raise ValueError("Unsupported NZIT template header")
    dt_start = HEADER + ((ksize + HEADER - 1) & ~(HEADER - 1))
    dt_end = dt_start + dtsize
    if dt_end + SIG > len(raw):
        raise ValueError("Truncated NZIT template sections")
    table = raw[dt_start:dt_end]
    magic, version, count = struct.unpack_from("<3I", table)
    if magic != 0x4e595845 or count != 6 or 12 + count * 20 > len(table):
        raise ValueError("Unsupported EXYN table profile")
    identities = []
    for i in range(count):
        plat, variant, rev, off, size = struct.unpack_from("<5I", table, 12 + i * 20)
        if off != DT_OFFSET or size != DT_SIZE or off + size > len(table):
            raise ValueError("EXYN entry differs from shared SM-R800 DTB profile")
        identities.append([plat, variant, rev])
    validate_dtb(table[DT_OFFSET:DT_OFFSET + DT_SIZE])
    return table, raw[dt_end:dt_end + SIG], align, ramdisk, identities


def validate_dtb(raw):
    if len(raw) != DT_SIZE:
        raise ValueError("Expected exact padded SM-R800 DTB size")
    nodes = parse_dtb(raw)
    root = nodes["/"]
    if strings(root.get("model", b"")) != ["GALILEO-LARGE-BT"] or \
            "samsung,exynos9110" not in strings(root.get("compatible", b"")):
        raise ValueError("DTB model or SoC does not identify SM-R800")
    return nodes


def component_evidence(dtb, kernel=None):
    """Check actual compiled components without creating an NZIT package."""
    nodes = validate_dtb(dtb)
    report = {"status": "DTB_STRUCTURE_ONLY", "model": "GALILEO-LARGE-BT",
              "dtb_bytes": len(dtb), "dtb_sha256": hashlib.sha256(dtb).hexdigest(),
              "dtb_nodes": len(nodes), "template_verified": False,
              "bootloader_verified": False, "safe_to_flash": False}
    if kernel is not None:
        if not 64 <= len(kernel) <= PARTITION or kernel[56:60] != b"ARM\x64":
            raise ValueError("Expected uncompressed ARM64 Linux Image")
        aligned = (len(kernel) + HEADER - 1) & ~(HEADER - 1)
        minimum = HEADER + aligned + DT_OFFSET + DT_SIZE + SIG
        if minimum > PARTITION:
            raise ValueError("Kernel and minimum DT table exceed partition budget")
        report.update({"status": "COMPILED_COMPONENTS_STRUCTURE_ONLY",
                       "kernel_bytes": len(kernel), "kernel_sha256": hashlib.sha256(kernel).hexdigest(),
                       "minimum_container_bytes": minimum,
                       "maximum_remaining_bytes": PARTITION - minimum,
                       "partition_size_verified": False})
    return report


def build(kernel, dtb, template):
    # ARM64 boot protocol magic is at offset 56 in the uncompressed Image.
    if not 64 <= len(kernel) <= PARTITION or kernel[56:60] != b"ARM\x64":
        raise ValueError("Expected uncompressed ARM64 Linux Image")
    validate_dtb(dtb)
    table, signature, align, ramdisk, identities = inspect_template(template)
    table = table[:DT_OFFSET] + dtb + table[DT_OFFSET + DT_SIZE:]
    header = struct.pack("<7I", 0x54495a4e, align, len(kernel),
                         len(kernel) + align, len(table), ramdisk, HEADER).ljust(HEADER, b"\0")
    padded = kernel.ljust((len(kernel) + HEADER - 1) & ~(HEADER - 1), b"\0")
    data = header + padded + table + signature
    if len(data) > PARTITION:
        raise ValueError("NZIT candidate exceeds SM-R800 partition size")
    data = data.ljust(PARTITION, b"\0")
    actual_table, actual_sig, _, _, actual_ids = inspect_template(data)
    if actual_table != table or actual_sig != signature or actual_ids != identities:
        raise ValueError("NZIT round-trip verification failed")
    return data


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ("kernel", "dtb", "template", "output"):
        p.add_argument("--" + name, type=Path, required=True)
    args = p.parse_args()
    data = build(read_regular(args.kernel, PARTITION),
                 read_regular(args.dtb, DT_SIZE),
                 read_regular(args.template, PARTITION))
    with args.output.open("xb") as stream:
        stream.write(data)
    print(json.dumps({"status": "NON_RELEASE_NZIT_STRUCTURE_ONLY",
                      "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(),
                      "signature_verified": False, "bootloader_verified": False,
                      "safe_to_flash": False}, sort_keys=True))


if __name__ == "__main__":
    main()
