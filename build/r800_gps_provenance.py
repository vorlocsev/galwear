#!/usr/bin/env python3
"""Record local GPS build inputs; not a signed attestation."""
import argparse
import hashlib
import json
from pathlib import Path

from r800_android_userspace_preflight import read_regular

LIMIT = 256 * 1024**2
HEADERS = ("gps_abi.h", "gps_command.h", "gps_frame.h", "gps_lto.h", "gps_output.h")


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
        expected = [str(tc / "clang"), "--target=armv7a-linux-gnueabi",
                    "-mfloat-abi=softfp", "-mfpu=vfpv3-d16",
                    "-DR800_XTRA_ABI=" + str(abi),
                    "--no-default-config", "-nostdinc", "-O2", "-fno-pic", "-no-pie",
                    "-fno-stack-protector", "-fno-builtin", "-ffreestanding",
                    "-nostdlib", "-fuse-ld=lld",
                    "-Wl,--hash-style=sysv", "-Wl,-z,noexecstack", "-Wl,-z,now",
                    "-Wl,--no-undefined", "-Wl,--dynamic-linker=/lib/ld-linux.so.3",
                    "-Wl,-e,_start", "-o", str(output),
                    str(root / "src/tools/gps/gpsbridge.c"),
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
                 "r800_pack_tizen_stage.py", "r800_verify_tizen_stage.py"):
        files[name] = root / "build" / name
    return {"schema": "galwear-r800-gps-inputs-v1", "argv": command,
            "inputs": {key: fingerprint(path) for key, path in files.items()},
            "compiler_contract": "freestanding-explicit-v1", "xtra_abi": abi,
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
        if args.mode == "capture":
            with args.record.open("x", encoding="utf-8") as stream:
                json.dump(record, stream, sort_keys=True)
        elif json.loads(read_regular(args.record, 1024**2)) != record:
            raise ValueError("Build inputs or compiler arguments changed")
    except (OSError, ValueError) as exc:
        parser.exit(2, "Provenance rejected: " + str(exc) + "\n")


if __name__ == "__main__":
    main()
