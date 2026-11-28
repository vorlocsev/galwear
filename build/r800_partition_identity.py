#!/usr/bin/env python3
"""Read-only filesystem and literal Android identity inventory of selected partitions.

EXT4: selected regular build.prop files via debugfs, no mount or guest execution.
EROFS: superblock geometry only, not a filesystem integrity check.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import struct
import tempfile

from r800_extract_ext4 import snapshot_image, locate, command
from r800_android_userspace_preflight import read_regular
from r800_graphics_donor_binding import checkout_sha
from r800_extract_super import ALLOWED, require
from r800_donor_preflight import digest

MAX_PROPERTIES = 1024*1024
MAX_PARTITION = 4*1024**3
KEYS = frozenset({
    "ro.build.id", "ro.build.fingerprint", "ro.build.version.release",
    "ro.build.version.sdk", "ro.build.version.security_patch",
    "ro.product.model", "ro.product.device", "ro.product.cpu.abi",
    "ro.product.cpu.abilist", "ro.product.cpu.abilist32",
    "ro.product.cpu.abilist64", "ro.build.characteristics",
    "ro.product.first_api_level", "ro.vndk.version",
} | {f"ro.{part}.build.{suffix}" for part in ("system", "vendor", "product", "system_ext", "odm")
     for suffix in ("id", "fingerprint", "version.release", "version.sdk")}
  | {f"ro.product.{part}.{suffix}" for part in ("system", "vendor", "product", "system_ext", "odm")
     for suffix in ("model", "device", "name", "brand", "manufacturer")})


def filesystem(path):
    with path.open("rb") as stream:
        stream.seek(1024)
        raw = stream.read(1024)
    require(len(raw) == 1024, "Truncated filesystem superblock")
    size = path.stat().st_size
    ext4 = raw[56:58] == b"\x53\xef"
    erofs = raw[:4] == b"\xe2\xe1\xf5\xe0"
    require(not (ext4 and erofs), "Ambiguous filesystem magic")
    if ext4:
        low = struct.unpack_from("<I", raw, 4)[0]
        log = struct.unpack_from("<I", raw, 24)[0]
        incompat = struct.unpack_from("<I", raw, 96)[0]
        require(log <= 6, "EXT4 block size outside supported range")
        block = 1024 << log
        high = struct.unpack_from("<I", raw, 336)[0] if incompat & 0x80 else 0
        blocks = low | high << 32
        kind = "EXT4"
    elif erofs:
        bits = raw[12]
        require(9 <= bits <= 16, "EROFS block size outside supported range")
        block = 1 << bits
        blocks = struct.unpack_from("<I", raw, 36)[0]
        kind = "EROFS"
    else:
        raise ValueError("Unsupported partition filesystem")
    require(blocks > 0 and 2048 <= block*blocks <= size, "Filesystem geometry exceeds partition")
    return {"kind": kind, "block_bytes": block, "blocks": blocks,
            "filesystem_bytes": block*blocks, "partition_bytes": size,
            "filesystem_integrity_verified": False}


def literal_properties(raw, path):
    records = []
    for number, line in enumerate(raw.decode("utf-8").splitlines(), 1):
        if line.lstrip().startswith("#"):
            continue
        key, sep, value = line.partition("=")
        key, value = key.strip(), value.strip()
        if not sep or key not in KEYS:
            continue
        require(0 < len(value) <= 512 and value.isprintable(),
                "Invalid literal property: " + key)
        records.append({"key": key, "value": value, "path": path, "line": number})
    return records


def property_inventory(records):
    values = {}
    for row in records:
        values.setdefault(row["key"], set()).add(row["value"])
    conflicts = sorted(k for k, v in values.items() if len(v) != 1)
    unique = {k: next(iter(v)) for k, v in sorted(values.items()) if len(v) == 1}
    sdk = unique.get("ro.build.version.sdk")
    release = unique.get("ro.build.version.release")
    abi = unique.get("ro.product.cpu.abilist", unique.get("ro.product.cpu.abi", ""))
    abi_list = abi.split(",") if abi else []
    allowed_abi = {"armeabi", "armeabi-v7a", "arm64-v8a", "x86", "x86_64", "riscv64"}
    return {"records": records, "unique_values": unique, "conflicts": conflicts,
            "literal_android_11_hint": sdk == "30" and release == "11" and not conflicts,
            "literal_arm32_hint": "armeabi-v7a" in abi_list and set(abi_list) <= allowed_abi and not conflicts,
            "literal_watch_hint": "watch" in unique.get("ro.build.characteristics", "").split(",") and not conflicts,
            "effective_properties_verified": False, "wear_os_version_verified": False}


def inspect_partition(image, expected, partition, source_sha):
    require(ALLOWED.fullmatch(partition), "Explicit allowed partition required")
    require(re.fullmatch(r"[0-9a-f]{64}", expected), "Expected partition SHA-256")
    checkout_sha(source_sha)
    image = Path(image)
    base = re.sub(r"_[ab]$", "", partition)
    with tempfile.TemporaryDirectory(prefix="r800-partition-identity-") as temp:
        scratch = Path(temp)
        copy = scratch/"partition.img"
        snapshot_image(image, copy, expected)
        fs = filesystem(copy)
        records, members = [], {}
        if fs["kind"] == "EXT4":
            tool = shutil.which("debugfs")
            require(tool, "debugfs required")
            candidates = ("/build.prop", f"/{base}/build.prop")
            for path in candidates:
                found = locate(tool, copy, path, MAX_PROPERTIES)
                if found is None:
                    continue
                inode, size = found
                dest = scratch/"property"
                try:
                    command(tool, copy, "dump <%d> property" % inode, cwd=scratch)
                    raw = read_regular(dest, MAX_PROPERTIES)
                    require(len(raw) == size, "Property member size mismatch")
                    members[path] = {"bytes": size, "sha256": hashlib.sha256(raw).hexdigest()}
                    records.extend(literal_properties(raw, path))
                finally:
                    dest.unlink(missing_ok=True)
        require(digest(copy, MAX_PARTITION)["sha256"] == expected, "Partition snapshot changed")
        require(digest(image, MAX_PARTITION)["sha256"] == expected, "Partition input changed")
    checkout_sha(source_sha)
    props = property_inventory(records)
    return {"schema": "galwear-r800-partition-identity-v1",
            "status": "EXT4_LITERAL_PROPERTIES_ONLY" if members and records and not props["conflicts"]
                      else "REVIEW_REQUIRED",
            "source_sha": source_sha, "partition": partition, "image_sha256": expected,
            "filesystem": fs, "property_members": members, "properties": props,
            "erofs_properties_supported": False, "donor_authenticity_verified": False,
            "wear_os_runtime_verified": False, "hardware_tested": False, "safe_to_flash": False}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--image", type=Path, required=True)
    p.add_argument("--sha256", required=True)
    p.add_argument("--partition", required=True)
    p.add_argument("--source-sha", required=True)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    report = inspect_partition(a.image, a.sha256, a.partition, a.source_sha)
    with a.output.open("x", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2, sort_keys=True)
        stream.write("\n")
    print(report["status"])
    return 0 if report["status"] == "EXT4_LITERAL_PROPERTIES_ONLY" else 2


if __name__ == "__main__":
    raise SystemExit(main())
