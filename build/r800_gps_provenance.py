#!/usr/bin/env python3
"""Record local GPS build inputs; not a signed attestation."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
from r800_gps_donor_snapshot import pinned_directory
from r800_gps_host_elf import audit as host_audit

from r800_android_userspace_preflight import read_regular

LIMIT = 256 * 1024**2
HEADERS = ("gps_abi.h", "gps_command.h", "gps_frame.h", "gps_lto.h", "gps_output.h")
SOURCES = ("gpsbridge.c", *HEADERS)
SOURCE_LIMIT = 4 * 1024**2
TOOLS = {"clang": "clang", "ld.lld": "lld", "llvm-readelf": "readelf"}


def source_snapshot(root, staging, record, *, create=False):
    """Check private, read-only copies against recorded checkout bytes.

    This detects persistent modifications, not a malicious same-UID process
    that can modify and restore files between checks.
    """
    source = root / "src/tools/gps"
    dest = staging / "sources"
    if create:
        dest.mkdir(mode=0o700)
    with pinned_directory(source) as (original, _):
        with pinned_directory(dest) as (snapshot, _):
            if create and list(snapshot.iterdir()):
                raise ValueError("Source snapshot is not empty")
            for name in SOURCES:
                key = "source" if name == "gpsbridge.c" else name
                raw = read_regular(original / name, SOURCE_LIMIT)
                expected = record["inputs"][key]["sha256"]
                if hashlib.sha256(raw).hexdigest() != expected:
                    raise ValueError("Checkout source changed: " + name)
                target = snapshot / name
                if create:
                    with target.open("xb") as stream:
                        stream.write(raw)
                    target.chmod(0o400)
                if (stat.S_IMODE(target.lstat().st_mode) != 0o400
                        or target.lstat().st_nlink != 1
                        or hashlib.sha256(read_regular(target, SOURCE_LIMIT)).hexdigest() != expected):
                    raise ValueError("Source snapshot changed: " + name)
            if {p.name for p in snapshot.iterdir()} != set(SOURCES):
                raise ValueError("Unexpected source snapshot entries")


def tool_snapshot(ndk, staging, record, *, create=False):
    """Copy selected NDK tool bytes; host libraries remain outside this boundary."""
    tc = ndk / "toolchains/llvm/prebuilt/linux-x86_64/bin"
    dest = staging / "tools"
    if create:
        dest.mkdir(mode=0o700)
    with pinned_directory(dest) as (snapshot, _):
        for name, key in TOOLS.items():
            source = (tc / name).resolve(strict=True)
            expected = record["inputs"][key]
            raw = read_regular(source, LIMIT)
            if str(source) != expected["resolved"] or hashlib.sha256(raw).hexdigest() != expected["sha256"]:
                raise ValueError("NDK tool changed: " + name)
            target = snapshot / name
            if create:
                with target.open("xb") as stream:
                    stream.write(raw)
                target.chmod(0o500)
            if (stat.S_IMODE(target.lstat().st_mode) != 0o500
                    or target.lstat().st_nlink != 1
                    or hashlib.sha256(read_regular(target, LIMIT)).hexdigest() != expected["sha256"]):
                raise ValueError("Tool snapshot changed: " + name)
        if {p.name for p in snapshot.iterdir()} != set(TOOLS):
            raise ValueError("Unexpected tool snapshot entries")


def validate_command(root, ndk, command):
    """Match the exact supported freestanding compiler contract."""
    tc = ndk / "toolchains/llvm/prebuilt/linux-x86_64/bin"
    if not isinstance(command, list) or not all(isinstance(arg, str) for arg in command):
        raise ValueError("Invalid compiler command")
    if len(command) < 3 or command.count("-o") != 1:
        raise ValueError("Unexpected compiler output")
    index = command.index("-o")
    if index + 1 >= len(command):
        raise ValueError("Missing compiler output")
    output = Path(command[index + 1])
    if not output.is_absolute() or output.name != "gpsbridge":
        raise ValueError("Unexpected compiler output path")
    staging = output.parent
    for abi in (0, 1, 2):
        expected = [str(staging / "tools/clang"), "--target=armv7a-linux-gnueabi",
                    "-mfloat-abi=softfp", "-mfpu=vfpv3-d16",
                    "-DR800_XTRA_ABI=" + str(abi),
                    "--no-default-config", "-nostdinc", "-O2", "-fno-pic", "-no-pie",
                    "-fno-stack-protector", "-fno-builtin", "-ffreestanding",
                    "-nostdlib", "-fuse-ld=lld", "--ld-path=" + str(staging / "tools/ld.lld"),
                    "-Wl,--hash-style=sysv", "-Wl,-z,noexecstack", "-Wl,-z,now",
                    "-Wl,--no-undefined", "-Wl,--dynamic-linker=/lib/ld-linux.so.3",
                    "-Wl,-e,_start", "-o", str(output),
                    str(staging / "sources/gpsbridge.c"),
                    *[str(staging / "libs" / name) for name in
                      ("libc.so.6", "libdl.so.2", "libpthread.so.0")]]
        if command == expected:
            return abi
    raise ValueError("Unexpected compiler arguments or input paths")


def fingerprint(path):
    # NDK tools may be symlinks. Include both resolved path and bytes.
    resolved = path.resolve(strict=True)
    return {"path": str(path), "resolved": str(resolved),
            "sha256": hashlib.sha256(read_regular(resolved, LIMIT)).hexdigest()}


def collect(root, ndk, command):
    tc = ndk / "toolchains/llvm/prebuilt/linux-x86_64/bin"
    abi = validate_command(root, ndk, command)
    files = {
        "ndk_revision": ndk / "source.properties",
        "clang": tc / "clang",
        "lld": tc / "ld.lld",
        "readelf": tc / "llvm-readelf",
        "source": root / "src/tools/gps/gpsbridge.c",
        "builder": root / "src/tools/gps/build.sh",
    }
    for name in HEADERS:
        files[name] = root / "src/tools/gps" / name
    for name in ("r800_gps_provenance.py", "r800_gps_donor_snapshot.py",
                 "r800_gps_publish.py", "r800_gps_link_gate.py",
                 "r800_android_userspace_preflight.py",
                 "r800_android_linker_audit.py", "r800_tizen_dependencies.py",
                 "r800_pack_tizen_stage.py", "r800_verify_tizen_stage.py",
                 "r800_gps_host_elf.py"):
        files[name] = root / "build" / name
    fingerprints = {key: fingerprint(path) for key, path in files.items()}
    fingerprints["host_elf"] = host_audit({name: tc / name for name in TOOLS})
    return {"schema": "galwear-r800-gps-inputs-v1", "argv": command,
            "inputs": fingerprints,
            "compiler_contract": "freestanding-snapshot-v3", "xtra_abi": abi,
            "tool_snapshot": TOOLS,
            "source_snapshot": {name: "source" if name == "gpsbridge.c" else name for name in SOURCES},
            "safe_to_flash": False, "signed_attestation": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("capture", "verify"))
    parser.add_argument("root", type=Path)
    parser.add_argument("ndk", type=Path)
    parser.add_argument("record", type=Path)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    try:
        record = collect(args.root, args.ndk, args.command)
        strict_host = os.environ.get("R800_REQUIRE_HOST_ELF", "0")
        if strict_host not in ("0", "1"):
            raise ValueError("Invalid R800_REQUIRE_HOST_ELF")
        if strict_host == "1" and record["inputs"]["host_elf"]["status"] != "HOST_STATIC_CANDIDATES_ONLY":
            raise ValueError("Host tool dependencies require review")
        staging = Path(args.command[args.command.index("-o") + 1]).parent
        if args.mode == "capture":
            source_snapshot(args.root, staging, record, create=True)
            tool_snapshot(args.ndk, staging, record, create=True)
            with args.record.open("x", encoding="utf-8") as stream:
                json.dump(record, stream, sort_keys=True)
        else:
            if json.loads(read_regular(args.record, 1024**2)) != record:
                raise ValueError("Build inputs or compiler arguments changed")
            source_snapshot(args.root, staging, record)
            tool_snapshot(args.ndk, staging, record)
    except (OSError, ValueError) as exc:
        parser.exit(2, "Provenance rejected: " + str(exc) + "\n")


if __name__ == "__main__":
    main()
