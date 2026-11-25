#!/usr/bin/env python3
"""Prepare and boot an allowlisted dynamic Android runtime in disposable virt.

Requires locally built or verified donor runtime and successful static Bionic
baseline. No generic archive input, network, disk device or firmware output.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess

from r800_android_dynamic_audit import inventory, inspect_elf, RUNTIME, LIBS, MAX_ELF
from r800_initramfs_spec import validate_init
from r800_qemu_guest_abi import read_bounded_json
from r800_qemu_system_init import kernel_bytes, observe_boot
from r800_qemu_user_init import EXPECTED, HEARTBEAT_PREFIX

MAX_ARCHIVE = 32 * 1024 * 1024
PROBE_PATH = "system/bin/galwear-dynamic-probe"
LINKER_PATH = RUNTIME + "/bin/linker64"
ALIAS = "../../apex/com.android.runtime/bin/linker64"
CONFIG = b"""# GalWear virt diagnostic only, not Android platform policy
dir.galwear = /system/bin
[galwear]
namespace.default.isolated = true
namespace.default.search.paths = /apex/com.android.runtime/lib64/bionic
namespace.default.permitted.paths = /apex/com.android.runtime/lib64/bionic
"""
DYNAMIC_MARKER = b"r800-dynamic: bionic api=30 dlopen=PASS dlsym=PASS"
CHILD_MARKER = b"r800-dynamic-pid1: child-exit=0"
DIRS = ("dev", "proc", "sys", "data", "system", "system/bin", "apex",
        RUNTIME, RUNTIME + "/bin", RUNTIME + "/lib64",
        RUNTIME + "/lib64/bionic", "linkerconfig")


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def snapshot(path: Path, expected: str, limit: int = MAX_ELF) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise ValueError("Missing or symlinked runtime file")
    with path.open("rb") as stream:
        data = stream.read(limit + 1)
    if not 0 < len(data) <= limit or sha(data) != expected:
        raise ValueError("Runtime file size or digest mismatch: " + path.name)
    return data


def newc(entries: list[tuple[str, int, bytes, int, int]]) -> bytes:
    """Serialize only the fixed allowlist; never accept donor-supplied paths."""
    expected = set(DIRS) | {"dev/console", "init", PROBE_PATH, LINKER_PATH,
                             "system/bin/linker64", "linkerconfig/ld.config.txt"}
    expected |= {RUNTIME + "/lib64/bionic/" + lib for lib in LIBS}
    if len(entries) != len(expected) or {e[0] for e in entries} != expected:
        raise ValueError("Unexpected dynamic archive entry set")
    seen = set()
    out = bytearray()
    for ino, (name, mode, data, major, minor) in enumerate(
            entries + [("TRAILER!!!", 0, b"", 0, 0)], 1):
        if "/" in name and name.rsplit("/", 1)[0] not in seen:
            raise ValueError("Archive parent missing")
        seen.add(name)
        pathname = name.encode("ascii") + b"\0"
        fields = (ino, mode, 0, 0, 2 if mode & 0o170000 == 0o040000 else 1,
                  0, len(data), 0, 0, major, minor, len(pathname), 0)
        out.extend(b"070701" + b"".join(f"{x:08x}".encode() for x in fields))
        out.extend(pathname)
        out.extend(bytes((-len(out)) % 4))
        out.extend(data)
        out.extend(bytes((-len(out)) % 4))
        if len(out) > MAX_ARCHIVE:
            raise ValueError("Dynamic archive exceeds RAM-only size limit")
    return bytes(out)


def prepare(init: Path, probe: Path, root: Path, runtime_report: Path, readelf: str):
    elf = validate_init(init)
    report = read_bounded_json(runtime_report)
    if (report.get("status") not in ("ANDROID_RUNTIME_EXTRACTED_STATIC_ONLY",
                                     "PINNED_GSI_RUNTIME_EXTRACTED_STATIC_ONLY")
            or report.get("safe_to_flash") is not False):
        raise ValueError("Successful runtime extraction evidence required")
    info = inventory(probe, root, readelf)
    root = root.resolve(strict=True)
    expected_files = {"bin/linker64"} | {"lib64/bionic/" + lib for lib in LIBS}
    records = report.get("files")
    if not isinstance(records, dict) or set(records) != expected_files:
        raise ValueError("Runtime extraction file set mismatch")
    entries = [(name, 0o040755, b"", 0, 0) for name in DIRS]
    entries.extend([("dev/console", 0o020600, b"", 5, 1),
                    ("init", 0o100755, snapshot(init, elf["sha256"]), 0, 0),
                    (PROBE_PATH, 0o100755, snapshot(probe, info["probe"]["sha256"]), 0, 0),
                    ("system/bin/linker64", 0o120777, ALIAS.encode(), 0, 0),
                    ("linkerconfig/ld.config.txt", 0o100644, CONFIG, 0, 0)])
    for relative in sorted(expected_files):
        path = root / RUNTIME / relative
        actual = inspect_elf(path, readelf)
        if actual != records[relative]:
            raise ValueError("Runtime extraction metadata mismatch: " + relative)
        if actual["elf_type"] != 3 or actual["interpreter"] is not None:
            raise ValueError("Unexpected runtime ELF type")
        if not set(actual["needed"]) <= set(LIBS):
            raise ValueError("Unexpected runtime dependency")
        if relative == "bin/linker64":
            if actual["needed"] or actual != info["linker64"]:
                raise ValueError("Linker metadata mismatch")
        elif actual["soname"] != path.name:
            raise ValueError("Runtime SONAME mismatch")
        if path.name in info["libraries"] and actual != info["libraries"][path.name]:
            raise ValueError("Runtime library changed during inventory")
        entries.append((RUNTIME + "/" + relative,
                        0o100755 if relative == "bin/linker64" else 0o100644,
                        snapshot(path, actual["sha256"]), 0, 0))
    archive = newc(entries)
    return archive, {"archive_sha256": sha(archive), "init_sha256": elf["sha256"],
                     "probe_sha256": info["probe"]["sha256"],
                     "linkerconfig_sha256": sha(CONFIG),
                     "runtime_sha256": {name: records[name]["sha256"] for name in sorted(records)},
                     "archive_entries": len(entries)}


def inspect_dynamic(log: bytes) -> dict:
    lines = log.replace(b"\r\n", b"\n").splitlines()
    marker = EXPECTED.rstrip(b"\n")
    if lines.count(marker) != 1 or lines.count(DYNAMIC_MARKER) != 1 or lines.count(CHILD_MARKER) != 1:
        raise ValueError("Missing or duplicate dynamic child evidence")
    if not lines.index(marker) < lines.index(DYNAMIC_MARKER) < lines.index(CHILD_MARKER):
        raise ValueError("Dynamic marker order mismatch")
    if any(line.startswith(HEARTBEAT_PREFIX) for line in lines[:lines.index(CHILD_MARKER)]):
        raise ValueError("Heartbeat before dynamic child completion")
    if [line for line in lines if line.startswith(b"r800-dynamic:")] != [DYNAMIC_MARKER]:
        raise ValueError("Unexpected dynamic diagnostic")
    return {"dynamic_android_linker_tested": True, "dlopen_dlsym_reported": True,
            "dynamic_child_exit_zero_reported": True}


def verify_baseline(path: Path, digest: str) -> None:
    base = read_bounded_json(path)
    if (base.get("status") != "VIRT_GUEST_BIONIC_ABI_ONLY"
            or base.get("generic_kernel_sha256") != digest
            or base.get("bionic_tested") is not True
            or base.get("guest_kernel_syscalls_tested") is not True
            or base.get("safe_to_flash") is not False):
        raise ValueError("Successful same-kernel static Bionic baseline required")


def run(a) -> dict:
    raw = kernel_bytes(a.kernel)
    kernel_sha = sha(raw)
    verify_baseline(a.baseline, kernel_sha)
    archive, report = prepare(a.init, a.probe, a.runtime_root, a.runtime_report, a.readelf)
    a.out_dir.mkdir(exist_ok=False)
    image = a.out_dir / "generic-Image"
    cpio = a.out_dir / "dynamic-initramfs.cpio"
    image.write_bytes(raw)
    cpio.write_bytes(archive)
    if sha(cpio.read_bytes()) != report["archive_sha256"]:
        raise ValueError("Archive changed before boot")
    command = ["qemu-system-aarch64", "-machine", "virt,gic-version=3,accel=tcg",
               "-cpu", "cortex-a53", "-smp", "2", "-m", "512M", "-nodefaults",
               "-no-reboot", "-display", "none", "-monitor", "none", "-serial", "stdio",
               "-nic", "none", "-kernel", str(image.resolve()),
               "-initrd", str(cpio.resolve()),
               "-append", "console=ttyAMA0 rdinit=/init ro loglevel=7 panic=-1"]
    log = a.out_dir / "generic-console.log"
    observed = observe_boot(command, log)
    if sha(cpio.read_bytes()) != report["archive_sha256"] or sha(image.read_bytes()) != kernel_sha:
        raise ValueError("Boot input changed during execution")
    return {**report, **observed, **inspect_dynamic(log.read_bytes()),
            "status": "VIRT_DYNAMIC_ANDROID_PROBE_ONLY",
            "generic_kernel_sha256": kernel_sha, "runtime_authenticity_verified": False,
            "android_framework_booted": False, "exynos9110_emulated": False,
            "safe_to_flash": False}


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    for arg in ("init", "probe", "runtime-root", "runtime-report", "kernel",
                "baseline", "out-dir", "report"):
        p.add_argument("--" + arg, type=Path, required=True)
    p.add_argument("--readelf", default="readelf")
    a = p.parse_args()
    try:
        report = run(a)
        rc = 0
    except (OSError, ValueError, TypeError, KeyError, IndexError, EOFError,
            subprocess.SubprocessError) as exc:
        report = {"status": "REJECT", "reason": str(exc),
                  "dynamic_android_linker_tested": False, "safe_to_flash": False}
        rc = 2
    a.report.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(report["status"])
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
