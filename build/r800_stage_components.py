#!/usr/bin/env python3
"""Assemble verified build outputs, not firmware, in a new partial candidate tree."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import struct
import tempfile
import zlib

from r800_android_userspace_preflight import read_regular
from r800_stage_hals import stage as stage_hals
from r800_vendor_inputs import file_info

TOOLS = ("bin/fsfreeze", "bin/loopdio", "bin/r800boost", "bin/r800keys", "bin/ukey",
         "bin/gpiotool", "bin/wpcd", "charger/r800charger",
         "charger/r800wdui", "charger/wpcd")
MISSING = ("Samsung combination firmware and verified NZIT template",
           "Clean Wear OS system image and matching base/J4 vendor images",
           "Complete donor HIDL services and dependency closure; libeffectsconfig.so",
           "Tizen glibc libraries and final linked GPSBridge",
           "BCMDHD STA/NVRAM/CLM and BCM43012 firmware",
           "Curated busybox, root, tzlite and lib trees",
           "Original charger digits and bootanimation frame; prepared display assets",
           "Independently prepared required persistent input; no device state copying",
           "PIT and recovery verification; physical acceptance")


def static_arm(data):
    if len(data) < 52 or data[:7] != b"\x7fELF\x01\x01\x01":
        raise ValueError("Expected ARM32 ELF")
    kind, machine = struct.unpack_from("<HH", data, 16)
    entry, phoff = struct.unpack_from("<II", data, 24)
    entsize, count = struct.unpack_from("<HH", data, 42)
    if (kind not in (2, 3) or machine != 40 or not entry or entsize != 32
            or not 1 <= count <= 128 or phoff + count * entsize > len(data)):
        raise ValueError("Invalid ARM32 executable headers")
    loads = 0
    for i in range(count):
        typ, off, addr, _, size, mem, flags, align = struct.unpack_from(
            "<IIIIIIII", data, phoff + i * entsize)
        if typ == 3:
            raise ValueError("Unexpected executable interpreter")
        if typ == 1:
            if off + size > len(data) or size > mem:
                raise ValueError("Invalid executable load segment")
            if flags & 1 and addr <= (entry & ~1) < addr + mem:
                loads += 1
        if typ == 2:
            if off + size > len(data) or size % 8:
                raise ValueError("Invalid dynamic segment")
            for p in range(off, off + size, 8):
                tag, value = struct.unpack_from("<iI", data, p)
                if tag == 0:
                    break
                if tag == 1:
                    raise ValueError("Unexpected DT_NEEDED")
    if not loads:
        raise ValueError("No executable entry segment")


def dex(data):
    if len(data) < 112 or data[:4] != b"dex\n" or data[7] != 0:
        raise ValueError("Invalid DEX header")
    if struct.unpack_from("<III", data, 32) != (len(data), 112, 0x12345678):
        raise ValueError("Invalid DEX size or endian marker")
    if data[12:32] != hashlib.sha1(data[32:]).digest():
        raise ValueError("Invalid DEX signature")
    if struct.unpack_from("<I", data, 8)[0] != zlib.adler32(data[12:]):
        raise ValueError("Invalid DEX checksum")


def assemble(hal_dir, vendor_sources, tools, bluetooth, keepwifi, output, source_sha):
    roots = [p.resolve(strict=True) for p in (hal_dir, vendor_sources, tools, bluetooth, keepwifi)]
    hal_dir, vendor_sources, tools, bluetooth, keepwifi = roots
    output = output.absolute()
    if output.exists() or output.is_symlink():
        raise ValueError("Output already exists")
    if any(output.resolve().is_relative_to(p) for p in roots):
        raise ValueError("Output must be outside input trees")
    with tempfile.TemporaryDirectory(dir=output.parent) as tmp:
        tree = Path(tmp) / "components"
        stage_hals(hal_dir, vendor_sources, tree)
        payload = tree / "payload"
        files = {}

        def add(src, dest, check=None, mode=0o644):
            raw = read_regular(src, 64*1024**2)
            if check:
                check(raw)
            dest.parent.mkdir(parents=True, exist_ok=True)
            with dest.open("xb") as out:
                out.write(raw)
            dest.chmod(mode)

        for name in TOOLS:
            add(tools / name, payload / name, static_arm, 0o755)
        if (payload / "bin/wpcd").read_bytes() != (payload / "charger/wpcd").read_bytes():
            raise ValueError("WPCD copies differ")
        bt = bluetooth / "libbt-vendor.so"
        file_info(bt, True)
        add(bt, payload / "fw/bt/libbt-vendor.so")
        add(vendor_sources / "libbt/bt_vendor.conf", payload / "fw/bt/bt_vendor.conf")
        add(keepwifi / "keepwifi.dex", payload / "keepwifi.dex", dex)
        # Never stage a relocatable object as a runnable GPS bridge.
        add(tools / "gpsbridge.o", tree / "unlinked/gpsbridge.o")
        for item in sorted(tree.rglob("*")):
            if item.is_file():
                raw = read_regular(item, 64*1024**2)
                files[item.relative_to(tree).as_posix()] = {
                    "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw),
                    "mode": oct(stat.S_IMODE(item.stat().st_mode))}
        report = {"status": "PARTIAL_COMPILED_COMPONENTS_ONLY", "source_sha": source_sha,
                  "files": files, "remaining_inputs_and_gates": list(MISSING),
                  "payload_complete": False, "vendor_image_built": False,
                  "runtime_verified": False, "safe_to_flash": False}
        (tree / "component-evidence.json").write_text(json.dumps(report, indent=2, sort_keys=True))
        os.rename(tree, output)
    return report


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for arg in ("hal-dir", "vendor-sources", "tools", "bluetooth", "keepwifi", "output"):
        p.add_argument("--" + arg, type=Path, required=True)
    p.add_argument("--source-sha", required=True)
    a = p.parse_args()
    print(json.dumps(assemble(a.hal_dir, a.vendor_sources, a.tools, a.bluetooth,
                              a.keepwifi, a.output, a.source_sha), sort_keys=True))


if __name__ == "__main__":
    main()
