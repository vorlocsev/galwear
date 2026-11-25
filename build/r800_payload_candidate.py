#!/usr/bin/env python3
"""Assemble an experimental payload from a curated local input tree, not a device backup."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import os
import stat
import sys
import tarfile
import tempfile

from r800_android_linker_audit import inspect
from r800_android_userspace_preflight import read_regular

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "installer"))
from r800_build_provenance import validate_payload

MAX_BYTES = 1800 * 1024**2
MAX_FILES = 30000
SCRIPTS = ("start.sh", "android-helper.sh", "dockrot.sh", "udhcpc.sh", "repair.sh")
HALS = ("audio.primary.r800.so", "gps.r800.so", "hwcomposer.r800.so", "sensors.r800.so")
BINS = ("busybox", "fsfreeze", "loopdio", "r800boost", "r800keys", "ukey", "wpcd")
DIRS = ("fw", "charger", "tzlite", "root", "lib")
SINGLE = ("keepwifi.dex", "gpsbridge", "splash.raw")
ASSET_SIZES = {"splash.raw": 360*360*4, "charger/pct.rgb": 36*110*3,
               "charger/bolt.rgb": 80*60*3}
ASSET_SIZES.update({"charger/d%d.rgb" % i: 55*110*3 for i in range(10)})
CHARGER_TOOLS = ("charger/r800charger", "charger/wpcd", "charger/r800wdui")
RADIO_FILES = ("fw/bcmdhd_sta.bin", "fw/nvram_net.txt", "fw/bcmdhd_clm.blob",
               "fw/bt/BCM43012B0_002.001.021.0153.0156.hcd",
               "fw/bt/bt_vendor.conf", "fw/bt/libbt-vendor.so")
STATE = {"DEV", "STAY", "SLEEP", "CPUIDLE_DEEP", "OVERLAY", "RESET_DATA", "TZTRACE",
         "GPU_SCALE", "DIAG", "gemini.tries", "userdata.img", "product_overlay", "props",
         "accounts.db", "accounts_ce.db", "accounts_de.db", "wpa_supplicant.conf",
         "bt_config.conf", ".mac.info", "hook.sh"}


def inventory(src, release):
    entries = {}
    total = 0
    def add(path, name, required=True, recursive=False):
        nonlocal total
        try:
            st = path.lstat()
        except FileNotFoundError:
            if required:
                raise
            return
        if any(ord(ch) < 32 or ch == "\\" for ch in name):
            raise ValueError("Unsafe payload member name")
        if name in entries or len(entries) >= MAX_FILES:
            raise ValueError("Payload member count or duplicate path")
        if path.name in STATE or path.name.lower().endswith((".log", ".bak", ".old", ".key", ".pem")):
            raise ValueError("State/debug artifact in curated payload: " + name)
        if stat.S_ISREG(st.st_mode):
            if not 0 <= st.st_size <= MAX_BYTES or total + st.st_size > MAX_BYTES:
                raise ValueError("Payload byte budget exceeded")
            if st.st_mode & (stat.S_ISUID | stat.S_ISGID):
                raise ValueError("Unexpected privileged mode: " + name)
            total += st.st_size
        elif stat.S_ISDIR(st.st_mode):
            if not recursive:
                raise ValueError("Expected regular payload file: " + name)
        elif stat.S_ISLNK(st.st_mode) and recursive:
            target = os.readlink(path)
            if not target or target.startswith("/") or "\\" in target or ".." in target.split("/"):
                raise ValueError("Unsafe payload symlink: " + name)
        else:
            raise ValueError("Unsupported payload input type: " + name)
        entries[name] = path
        if stat.S_ISDIR(st.st_mode):
            for child in sorted(path.iterdir()):
                add(child, name + "/" + child.name, recursive=True)

    def checked(relative, root=src):
        path = root / relative
        # Do not follow source symlinks while resolving explicitly selected files.
        if path.resolve(strict=False) != path:
            raise ValueError("Symlinked selected input: " + relative)
        return path

    system = [n for n in ("system.img", "system.sqfs") if checked("android/" + n).is_file()]
    if len(system) != 1:
        raise ValueError("Supply exactly one curated system.img or system.sqfs")
    for name in system:
        p = checked("android/" + name)
        with p.open("rb") as f:
            header = f.read(1082)
        if (name.endswith(".sqfs") and header[:4] != b"hsqs" or
                name.endswith(".img") and header[1080:1082] != b"\x53\xef"):
            raise ValueError("Invalid Android system image magic")
        add(p, "android/" + name)
    # The existing build contract expects an independently prepared blank
    # persistent image. Never copy one from a watch or create/reset it here.
    add(checked("android/persistent.img"), "android/persistent.img")
    for name in ("mediacodec.policy", "empty-permissions.xml"):
        add(checked("android/" + name), "android/" + name, required=False)
    add(checked("android/overlay"), "android/overlay", required=False, recursive=True)
    for name in HALS:
        path = checked("hwc/" + name)
        add(path, "hwc/" + name)
        elf = inspect(read_regular(path, 64 * 1024**2))
        if elf["abi"] != "arm" or elf["elf_type"] != "ET_DYN" or not elf["has_dynamic"]:
            raise ValueError("Expected ARM32 HAL: " + name)
    for name in BINS:
        path = checked("bin/" + name)
        add(path, "bin/" + name)
        if not path.stat().st_mode & 0o111:
            raise ValueError("Non-executable payload binary: " + name)
    for name in DIRS:
        add(checked(name), name, recursive=True)
    # Require the specific firmware paths used by the configured bcmdhd driver
    # and Broadcom vendor library. Names/hashes are not proof of compatibility.
    for name in RADIO_FILES:
        if name not in entries:
            raise ValueError("Missing radio input: " + name)
        path = checked(name)
        raw = read_regular(path, 64 * 1024**2)
        if name.endswith(".so"):
            elf = inspect(raw)
            if elf["abi"] != "arm" or elf["elf_type"] != "ET_DYN" or not elf["has_dynamic"]:
                raise ValueError("Expected ARM32 Bluetooth vendor library")
        elif name.endswith("bt_vendor.conf"):
            expected = read_regular(checked("src/vendor/libbt/bt_vendor.conf", release), 65536)
            if raw != expected:
                raise ValueError("Bluetooth configuration differs from repository profile")
    for name in SINGLE:
        add(checked(name), name)
    for name, size in ASSET_SIZES.items():
        if name not in entries:
            raise ValueError("Missing display asset: " + name)
        path = checked(name)
        if not stat.S_ISREG(path.lstat().st_mode) or path.stat().st_size != size:
            raise ValueError("Invalid display asset size: " + name)
    for name in CHARGER_TOOLS:
        if name not in entries:
            raise ValueError("Missing charger tool: " + name)
        path = checked(name)
        if not stat.S_ISREG(path.lstat().st_mode) or not path.stat().st_mode & 0o111:
            raise ValueError("Non-executable charger tool: " + name)
    if hashlib.sha256(read_regular(checked("charger/wpcd"), 64*1024**2)).digest() != hashlib.sha256(read_regular(checked("bin/wpcd"), 64*1024**2)).digest():
        raise ValueError("Charger and Android WPCD bytes differ")
    for name in SCRIPTS:
        add(checked("payload/" + name, release), name)
    add(checked("src/tools/sensors/tzchroot.sh", release), "tzchroot.sh")
    return entries, total


def build(src, release, output):
    src, release = src.resolve(strict=True), release.resolve(strict=True)
    output = output.absolute()
    if output.exists() or output.is_symlink():
        raise ValueError("Output already exists")
    if output.resolve().is_relative_to(src) or output.resolve().is_relative_to(release):
        raise ValueError("Output must be outside input trees")
    entries, total = inventory(src, release)
    with tempfile.TemporaryDirectory(dir=output.parent) as tmp:
        candidate = Path(tmp) / "candidate.tar"
        with tarfile.open(candidate, "w", format=tarfile.PAX_FORMAT, dereference=True) as tar:
            for name in ("", "android", "bin", "hwc"):
                info = tarfile.TarInfo("r800dev" + ("/" + name if name else ""))
                info.type, info.mode = tarfile.DIRTYPE, 0o755
                tar.addfile(info)
            # Preserve allowed relative symlinks; no recursive tar.add and no hardlinks.
            tar.dereference = False
            for name, path in sorted(entries.items()):
                info = tar.gettarinfo(str(path), "r800dev/" + name)
                if info.islnk():
                    raise ValueError("Hardlinked payload input: " + name)
                # Preserve numeric ownership: chroot libraries and daemons may require it.
                info.uname = info.gname = ""
                info.mtime = 0
                if name in SCRIPTS or name == "tzchroot.sh":
                    info.mode = 0o755
                if info.isfile():
                    with path.open("rb") as stream:
                        tar.addfile(info, stream)
                else:
                    tar.addfile(info)
            # Create only the boot selection marker, not copied device flags.
            info = tarfile.TarInfo("r800dev/android/BOOT_ANDROID")
            info.mode = 0o644
            tar.addfile(info)
        validated = validate_payload(candidate)
        if candidate.stat().st_size > MAX_BYTES:
            raise ValueError("Archive exceeds payload budget")
        # Atomic no-overwrite publication on the same filesystem.
        os.link(candidate, output)
    h = hashlib.sha256()
    with output.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return {"status": "NON_RELEASE_PAYLOAD_STRUCTURE_ONLY", "source_bytes": total,
            "sha256": h.hexdigest(), "archive_bytes": output.stat().st_size,
            "archive_inventory": validated, "embedded_image_contents_verified": False,
            "device_state_absence_verified": False, "xattrs_preserved_verified": False,
            "safe_to_flash": False}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ("source", "release", "output"):
        p.add_argument("--" + name, type=Path, required=True)
    args = p.parse_args()
    print(json.dumps(build(args.source, args.release, args.output), sort_keys=True))


if __name__ == "__main__":
    main()
